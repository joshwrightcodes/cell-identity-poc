package gwapi

import "sync"

// Notifier wakes the streams of a cell when the gateway has new work for it.
type Notifier struct {
	mu   sync.Mutex
	subs map[string]map[*subscription]struct{}
}

type subscription struct{ ch chan struct{} }

// NewNotifier returns a Notifier with no subscriber.
func NewNotifier() *Notifier {
	return &Notifier{subs: map[string]map[*subscription]struct{}{}}
}

// Notify sends one signal to each subscriber of cell. It never blocks: a subscriber that has a
// signal waiting gets no second one.
func (n *Notifier) Notify(cell string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for s := range n.subs[cell] {
		select {
		case s.ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a channel that receives a signal after Notify(cell), and a function that stops
// the delivery. The channel holds one signal, so several notifies in a row give one signal. The
// function is safe to call twice.
func (n *Notifier) Subscribe(cell string) (<-chan struct{}, func()) {
	s := &subscription{ch: make(chan struct{}, 1)}
	n.mu.Lock()
	if n.subs[cell] == nil {
		n.subs[cell] = map[*subscription]struct{}{}
	}
	n.subs[cell][s] = struct{}{}
	n.mu.Unlock()
	return s.ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.subs[cell], s)
		if len(n.subs[cell]) == 0 {
			delete(n.subs, cell)
		}
	}
}
