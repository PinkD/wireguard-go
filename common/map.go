package common

import "sync"

type SyncMap[K comparable, V any] struct {
	m sync.Map
}

func (m *SyncMap[K, V]) Load(k K) (V, bool) {
	v, ok := m.m.Load(k)
	if !ok {
		var nv V
		return nv, false
	}
	return v.(V), true
}

func (m *SyncMap[K, V]) Store(k K, v V) {
	m.m.Store(k, v)
}

func (m *SyncMap[K, V]) LoadOrStore(k K, v V) (V, bool) {
	value, ok := m.m.LoadOrStore(k, v)
	return value.(V), ok
}

func (m *SyncMap[K, V]) LoadAndDelete(k K) (V, bool) {
	value, ok := m.m.LoadAndDelete(k)
	return value.(V), ok
}

func (m *SyncMap[K, V]) Delete(k K) {
	m.m.Delete(k)
}

func (m *SyncMap[K, V]) Range(f func(k K, v V) bool) {
	m.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
