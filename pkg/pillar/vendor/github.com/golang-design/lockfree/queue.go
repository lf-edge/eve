package lockfree

import (
	"sync/atomic"
	"unsafe"
)

// Queue implements lock-free FIFO freelist based queue.
// ref: https://dl.acm.org/citation.cfm?doid=248052.248106
type Queue struct {
	head unsafe.Pointer
	tail unsafe.Pointer
	len  uint64
}

// NewQueue creates a new lock-free queue.
func NewQueue() *Queue {
	head := queueitem{next: nil, v: nil} // allocate a free item
	return &Queue{
		tail: unsafe.Pointer(&head), // both head and tail points
		head: unsafe.Pointer(&head), // to the free item
	}
}

// Enqueue puts the given value v at the tail of the queue.
func (q *Queue) Enqueue(v interface{}) {
	item := &queueitem{next: nil, v: v} // allocate new item
	var last, lastnext *queueitem
	for {
		last = loadqitem(&q.tail)
		lastnext = loadqitem(&last.next)
		if loadqitem(&q.tail) == last { // are tail and next consistent?
			if lastnext == nil { // was tail pointing to the last node?
				if casqitem(&last.next, lastnext, item) { // try to link item at the end of linked list
					casqitem(&q.tail, last, item) // enqueue is done. try swing tail to the inserted node
					atomic.AddUint64(&q.len, 1)
					return
				}
			} else { // tail was not pointing to the last node
				casqitem(&q.tail, last, lastnext) // try swing tail to the next node
			}
		}
	}
}

// Dequeue removes and returns the value at the head of the queue.
// It returns nil if the queue is empty.
func (q *Queue) Dequeue() interface{} {
	var first, last, firstnext *queueitem
	for {
		first = loadqitem(&q.head)
		last = loadqitem(&q.tail)
		firstnext = loadqitem(&first.next)
		if first == loadqitem(&q.head) { // are head, tail and next consistent?
			if first == last { // is queue empty?
				if firstnext == nil { // queue is empty, couldn't dequeue
					return nil
				}
				casqitem(&q.tail, last, firstnext) // tail is falling behind, try to advance it
			} else { // read value before cas, otherwise another dequeue might free the next node
				v := firstnext.v
				if casqitem(&q.head, first, firstnext) { // try to swing head to the next node
					atomic.AddUint64(&q.len, ^uint64(0))
					return v // queue was not empty and dequeue finished.
				}
			}
		}
	}
}

// Length returns the length of the queue.
func (q *Queue) Length() uint64 {
	return atomic.LoadUint64(&q.len)
}

type queueitem struct {
	next unsafe.Pointer
	v    interface{}
}

func loadqitem(p *unsafe.Pointer) *queueitem {
	return (*queueitem)(atomic.LoadPointer(p))
}
func casqitem(p *unsafe.Pointer, old, new *queueitem) bool {
	return atomic.CompareAndSwapPointer(p, unsafe.Pointer(old), unsafe.Pointer(new))
}
