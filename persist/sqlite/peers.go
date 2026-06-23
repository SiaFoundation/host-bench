package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.sia.tech/coreutils/syncer"
	"go.uber.org/zap"
)

// A PeerStore stores information about peers.
type PeerStore struct {
	s *Store

	mu       sync.Mutex
	peerInfo map[string]syncer.PeerInfo
}

var _ syncer.PeerStore = (*PeerStore)(nil)

// NewPeerStore creates a new peer store backed by the given Store.
func NewPeerStore(s *Store) (syncer.PeerStore, error) {
	ps := &PeerStore{s: s, peerInfo: make(map[string]syncer.PeerInfo)}
	peers, err := s.Peers()
	if err != nil {
		return nil, fmt.Errorf("failed to load peers: %w", err)
	}
	for _, pi := range peers {
		ps.peerInfo[pi.Address] = pi
	}
	return ps, nil
}

// AddPeer adds the given peer to the store.
func (ps *PeerStore) AddPeer(peer string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.peerInfo[peer]; !exists {
		ps.peerInfo[peer] = syncer.PeerInfo{
			Address:   peer,
			FirstSeen: time.Now(),
		}
	}
	return ps.s.AddPeer(peer)
}

// Peers returns all known peers.
func (ps *PeerStore) Peers() ([]syncer.PeerInfo, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	peers := make([]syncer.PeerInfo, 0, len(ps.peerInfo))
	for _, pi := range ps.peerInfo {
		peers = append(peers, pi)
	}
	return peers, nil
}

// PeerInfo returns the metadata for the given peer.
func (ps *PeerStore) PeerInfo(peer string) (syncer.PeerInfo, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if pi, ok := ps.peerInfo[peer]; ok {
		return pi, nil
	}
	return syncer.PeerInfo{}, syncer.ErrPeerNotFound
}

// UpdatePeerInfo updates peer metadata.
func (ps *PeerStore) UpdatePeerInfo(peer string, fn func(*syncer.PeerInfo)) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	pi, ok := ps.peerInfo[peer]
	if !ok {
		return syncer.ErrPeerNotFound
	}
	fn(&pi)
	ps.peerInfo[peer] = pi
	return nil
}

// Ban temporarily bans the given peer.
func (ps *PeerStore) Ban(peer string, duration time.Duration, reason string) error {
	return ps.s.Ban(peer, duration, reason)
}

// Banned returns true if the peer is currently banned.
func (ps *PeerStore) Banned(peer string) (bool, error) {
	return ps.s.Banned(peer)
}

func scanPeerInfo(s scanner) (pi syncer.PeerInfo, err error) {
	err = s.Scan(&pi.Address, decode(&pi.FirstSeen))
	return
}

// AddPeer persists a peer address.
func (s *Store) AddPeer(peer string) error {
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`INSERT INTO syncer_peers (peer_address, first_seen) VALUES (?, ?) ON CONFLICT (peer_address) DO NOTHING`, peer, encode(time.Now()))
		return err
	})
}

// Peers returns persisted peer addresses.
func (s *Store) Peers() (peers []syncer.PeerInfo, err error) {
	err = s.transaction(func(tx txn) error {
		rows, err := tx.Query(`SELECT peer_address, first_seen FROM syncer_peers`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			peer, err := scanPeerInfo(rows)
			if err != nil {
				return fmt.Errorf("failed to scan peer info: %w", err)
			}
			peers = append(peers, peer)
		}
		return rows.Err()
	})
	return
}

func normalizePeer(peer string) (string, error) {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		host = peer
	}
	if strings.IndexByte(host, '/') != -1 {
		_, subnet, err := net.ParseCIDR(host)
		if err != nil {
			return "", fmt.Errorf("failed to parse CIDR: %w", err)
		}
		return subnet.String(), nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid IP address")
	}

	maskLen := 128
	if ip.To4() != nil {
		maskLen = 32
	}

	_, normalized, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), maskLen))
	if err != nil {
		panic("failed to parse CIDR")
	}
	return normalized.String(), nil
}

// Ban temporarily bans one or more IPs.
func (s *Store) Ban(peer string, duration time.Duration, reason string) error {
	address, err := normalizePeer(peer)
	if err != nil {
		return err
	}
	s.log.Debug("banning peer", zap.String("peer", address), zap.Duration("duration", duration), zap.String("reason", reason))
	return s.transaction(func(tx txn) error {
		_, err := tx.Exec(`INSERT INTO syncer_bans (net_cidr, expiration, reason) VALUES (?, ?, ?) ON CONFLICT (net_cidr) DO UPDATE SET expiration=excluded.expiration, reason=excluded.reason`, address, encode(time.Now().Add(duration)), reason)
		return err
	})
}

// Banned returns true if the peer is currently banned.
func (s *Store) Banned(peer string) (banned bool, err error) {
	peer, err = normalizePeer(peer)
	if err != nil {
		return false, fmt.Errorf("failed to normalize peer: %w", err)
	}

	_, subnet, err := net.ParseCIDR(peer)
	if err != nil {
		return false, fmt.Errorf("failed to parse CIDR: %w", err)
	}

	maxMaskLen := 128
	if subnet.IP.To4() != nil {
		maxMaskLen = 32
	}

	checkSubnets := make([]string, 0, maxMaskLen)
	for i := maxMaskLen; i > 0; i-- {
		_, subnet, err := net.ParseCIDR(subnet.IP.String() + "/" + strconv.Itoa(i))
		if err != nil {
			panic("failed to parse CIDR")
		}
		checkSubnets = append(checkSubnets, subnet.String())
	}

	err = s.transaction(func(tx txn) error {
		checkSubnetStmt, err := tx.Prepare(`SELECT expiration FROM syncer_bans WHERE net_cidr = ? ORDER BY expiration DESC LIMIT 1`)
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer checkSubnetStmt.Close()

		for _, subnet := range checkSubnets {
			var expiration time.Time
			err := checkSubnetStmt.QueryRow(subnet).Scan(decode(&expiration))
			banned = time.Now().Before(expiration)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to check ban status: %w", err)
			} else if banned {
				s.log.Debug("found ban", zap.String("subnet", subnet), zap.Time("expiration", expiration))
				return nil
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("failed to check ban status: %w", err)
	}
	return banned, nil
}
