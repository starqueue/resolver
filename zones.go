package resolver

import (
	"github.com/miekg/dns"
	"slices"
	"sync"
)

type zoneStore interface {
	getZoneList(name string) []zone
	get(name string) zone
	add(z zone)
	count() int
}

// zones is a thread-safe map of <zone name> -> zone.
type zones struct {
	lock  sync.RWMutex
	zones map[string]zone
}

func (zones *zones) getZoneList(name string) []zone {
	name = canonicalName(name)

	indexes := append(dns.Split(name), len(name)-1)
	slices.Reverse(indexes)

	zones.lock.RLock()
	defer zones.lock.RUnlock()

	if zones.zones == nil {
		return nil
	}

	var last zone
	result := make([]zone, 0, len(indexes))
	for _, idx := range indexes {
		zname := name[idx:]

		z, _ := zones.zones[zname]

		// Skip the zone if missing
		if z == nil || z.expired() {
			continue
		}

		// If the zone is found, but the parent don't alight with the last seen zone, then we're done.
		if last != nil && z.parent() != last.name() {
			break
		}

		result = append(result, z)
		last = z
	}

	slices.Reverse(result)
	return result
}

func (zones *zones) get(name string) zone {
	name = canonicalName(name)
	zones.lock.RLock()
	defer zones.lock.RUnlock()

	if zones.zones == nil {
		return nil
	}

	z, _ := zones.zones[name]

	if z != nil && z.expired() {
		// We could remove the expired zone from the map here, but realistically it's about to be replaced,
		// so we'll opt to keep things simple here (keeping get() read-only) and just return the result.
		return nil
	}

	return z
}

func (zones *zones) add(z zone) {
	name := canonicalName(z.name())
	zones.lock.Lock()
	if zones.zones == nil {
		zones.zones = make(map[string]zone)
	}
	zones.zones[name] = z
	needsCleanup := len(zones.zones) > 0 && len(zones.zones)%100 == 0
	zones.lock.Unlock()

	// Run cleanup outside the lock to avoid blocking readers.
	if needsCleanup {
		zones.cleanup()
	}
}

// cleanup removes expired zones. Acquires write lock only for the
// delete phase, after collecting expired keys with a read lock.
func (zones *zones) cleanup() {
	zones.lock.RLock()
	var expired []string
	for k, v := range zones.zones {
		if v.expired() {
			expired = append(expired, k)
		}
	}
	zones.lock.RUnlock()

	if len(expired) == 0 {
		return
	}

	zones.lock.Lock()
	for _, k := range expired {
		// Re-check under write lock — zone may have been replaced.
		if v, ok := zones.zones[k]; ok && v.expired() {
			delete(zones.zones, k)
		}
	}
	zones.lock.Unlock()
}

func (zones *zones) count() int {
	zones.lock.RLock()
	c := len(zones.zones)
	zones.lock.RUnlock()
	return c
}
