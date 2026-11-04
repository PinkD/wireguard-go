// SPDX-License-Identifier: MIT
// Adapted from the go-socks5 UDP association flow. Copyright (c) 2014 Armon
// Dadgar. The upstream MIT notice is reproduced in socks5.LICENSE.

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type socksDial func(context.Context, string, string) (net.Conn, error)

// udpAssociateHandler keeps listener ownership in the request handler, including
// failed replies, and waits for its forwarding goroutines during shutdown.
func udpAssociateHandler(dial socksDial) socks5.Handler {
	return func(ctx context.Context, writer io.Writer, req *socks5.Request) error {
		client, ok := writer.(net.Conn)
		local, localOK := req.LocalAddr.(*net.TCPAddr)
		if !ok || !localOK || local == nil {
			return errors.New("UDP ASSOCIATE requires a TCP connection")
		}
		// Enforce the identity rule here too, even when called without middleware.
		if err := bindUDPAssociation(ctx, writer, req); err != nil {
			return err
		}
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
		if err != nil {
			socks5.SendReply(writer, statute.RepServerFailure, nil)
			return err
		}
		defer relay.Close()
		if err := socks5.SendReply(writer, statute.RepSuccess, relay.LocalAddr()); err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var mu sync.Mutex
		var stopped bool
		targets := make(map[string]net.Conn)
		var relayWG, repliesWG sync.WaitGroup
		drop := func(key string, target net.Conn) {
			mu.Lock()
			if targets[key] == target {
				delete(targets, key)
			}
			mu.Unlock()
			target.Close()
		}
		relayWG.Add(1)
		go func() {
			defer relayWG.Done()
			defer client.Close() // wake the control reader if the relay fails
			buf := make([]byte, 65535)
			for {
				n, source, err := relay.ReadFromUDP(buf)
				if err != nil {
					return
				}
				if !source.IP.Equal(req.DestAddr.IP) || source.Port != req.DestAddr.Port {
					continue
				}
				packet, err := statute.ParseDatagram(buf[:n])
				if err != nil || packet.Frag != 0 {
					continue // SOCKS UDP fragmentation is unsupported
				}
				key := packet.DstAddr.String()
				mu.Lock()
				target := targets[key]
				mu.Unlock()
				if target == nil {
					target, err = dial(ctx, "udp", key)
					if err != nil {
						continue
					}
					mu.Lock()
					if stopped {
						mu.Unlock()
						target.Close()
						return
					}
					targets[key] = target
					mu.Unlock()
					// IPv6 addresses in ParseDatagram alias buf. Copy the header
					// before the next packet can overwrite that shared storage.
					header := append([]byte(nil), packet.Header()...)
					repliesWG.Add(1)
					go func(target net.Conn, key string, header []byte, source *net.UDPAddr) {
						defer repliesWG.Done()
						defer drop(key, target)
						response := make([]byte, 65535)
						copy(response, header)
						for {
							n, err := target.Read(response[len(header):])
							if err != nil {
								return
							}
							if n+len(header) > 65507 {
								continue
							}
							if _, err := relay.WriteToUDP(response[:len(header)+n], source); err != nil {
								return
							}
						}
					}(target, key, header, source)
				}
				if _, err := target.Write(packet.Data); err != nil {
					drop(key, target)
				}
			}
		}()

		_, err = io.Copy(io.Discard, req.Reader)
		cancel()
		relay.Close()
		mu.Lock()
		stopped = true
		pending := make([]net.Conn, 0, len(targets))
		for _, target := range targets {
			pending = append(pending, target)
		}
		mu.Unlock()
		for _, target := range pending {
			target.Close()
		}
		relayWG.Wait() // no further repliesWG.Add calls after this point
		repliesWG.Wait()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}
