package audit

import (
	"context"
	"sync"
)

// Store is the append-only backing store for audit events. It offers no
// update or delete — append-only is enforced by the shape of the
// interface, not by convention. The query and subscribe primitives are
// what the CLI's log/tail verbs and the dashboard's audit viewer consume.
//
// The production store targets its own object storage with its own
// retention (build-plan Phases 1 and 6). MemStore is the in-memory
// implementation used by tests and by the break-glass paths that run
// before that store is reachable.
type Store interface {
	// Append durably records one event.
	Append(ctx context.Context, e Event) error
	// Query returns every stored event matching the filter, in append
	// order.
	Query(ctx context.Context, f Filter) ([]Event, error)
	// Subscribe returns a channel of events appended after the call.
	// The channel is closed when ctx is done. A subscriber that cannot
	// keep up misses events rather than blocking the writer.
	Subscribe(ctx context.Context) <-chan Event
}

// MemStore is an in-memory, append-only Store.
type MemStore struct {
	mu     sync.Mutex
	events []Event
	subs   []chan Event
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// Append records e and fans it out to live subscribers.
func (s *MemStore) Append(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	for _, ch := range s.subs {
		// Non-blocking send under the lock: a slow subscriber misses
		// the event rather than stalling the writer, and holding the
		// lock keeps Append from racing the close in Subscribe.
		select {
		case ch <- e:
		default:
		}
	}
	return nil
}

// Query returns the stored events matching f, in append order.
func (s *MemStore) Query(_ context.Context, f Filter) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if f.matches(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Subscribe registers a live event channel, unregistered and closed when
// ctx is done.
func (s *MemStore) Subscribe(ctx context.Context) <-chan Event {
	ch := make(chan Event, 64)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
		close(ch)
	}()
	return ch
}
