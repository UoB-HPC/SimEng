#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace simeng {

/** A class that builds a memory pool with fixed `chunk_size`. It uses a free
 * list to keep track of free memory. The list is stored within the memory used
 * by the pool. */
template <size_t chunk_size, size_t initial_size = 2>
class fixedPool_ {
  static_assert(initial_size && (initial_size & (initial_size - 1)) == 0 &&
                "initial_size is not a power of 2");

 public:
  ~fixedPool_() {
    for (auto& ptr : ptrs) operator delete(ptr);
  }

  /** Allocate `chunk_size` bytes. If allocation fails, it returns nullptr. */
  void* allocate() noexcept {
    if (head) {
      return std::exchange(head, *reinterpret_cast<void**>(head));
    } else {
      return grow() ? allocate() : head;
    }
  }

  /** Return memory at `ptr` of size `chunk_size` bytes to the memory pool.
   * Passing nullptr is a nop. */
  void deallocate(void* ptr) noexcept {
    if (ptr) {
      *reinterpret_cast<void**>(ptr) = head;
      head = ptr;
    }
  }

 private:
  /** Allocate more memory and add new chunks to the free list. */
  bool grow() noexcept {
    // The space in bytes needed to fit `n_allocated` aligned chunks.
    size_t space = sizeof(chunk) * n_allocated;

    void* ptr = operator new(space, std::nothrow);
    if (!ptr) return ptr;

    ptrs.push_back(ptr);

    // Go through each chunk and add a new free list node. The node consists of
    // an address to the next free chunk (nullptr if it is the last node).
    while (std::align(alignof(std::max_align_t), chunk_size, ptr, space)) {
      auto temp = std::exchange(head, ptr);
      *reinterpret_cast<void**>(ptr) = temp;
      ptr = (char*)ptr + chunk_size;
      space -= chunk_size;
    }

    n_allocated = n_allocated << 1;

    return head;
  }

  // A helper struct used to calculate how much padding is needed to
  // allocate aligned chunks.
  struct chunk {
    alignas(std::max_align_t) unsigned char data[chunk_size];
  };

  // Pointer to the head of the free list.
  void* head = nullptr;

  // No. of chunks to allocate in the next block.
  std::size_t n_allocated = initial_size;

  // Vector of all the pointers returned from operator new.
  std::vector<void*> ptrs;
};

/** The class Pool is general-purpose memory pool implementation. It consists of
 * a collection of pools that serve requests for different chunk sizes.
 *
 * Allocations requests that exceed the largest chunk size supported are served
 * from the free store directly. Currently the largest chunk size supported is
 * 512 bytes.
 *
 * All memory is freed on destruction even if deallocate has not been
 * called. If memory is exhausted, a block of memory is allocated. The size of
 * blocks increases by a factor of 2. */
class Pool {
 public:
  /** Allocates `bytes` with alignment `alignof(std::max_align_t)`. If memory in
   * the pool is exhausted, a block of memory is allocated from the free
   * store. */
  void* allocate(uint32_t bytes) {
    switch (roundUp(bytes)) {
      case 32:
        return pool32.allocate();
      case 64:
        return pool64.allocate();
      case 128:
        return pool128.allocate();
      case 256:
        return pool256.allocate();
      case 512:
        return pool512.allocate();
      default:
        return ::operator new(bytes);
    };
  }

  /** Returns the memory at `ptr` to the memory pool. If `ptr` is a nullptr, it
   * is a nop. */
  void deallocate(void* ptr, uint32_t bytes) noexcept {
    switch (roundUp(bytes)) {
      case 32:
        pool32.deallocate(ptr);
        break;
      case 64:
        pool64.deallocate(ptr);
        break;
      case 128:
        pool128.deallocate(ptr);
        break;
      case 256:
        pool256.deallocate(ptr);
        break;
      case 512:
        pool512.deallocate(ptr);
        break;
      default:
        ::operator delete(ptr);
        break;
    };
  }

 private:
  /** Round up to the nearest power of 2 that is greater than or equal to v. */
  uint32_t roundUp(uint32_t v) {
    --v;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return ++v;
  }

  fixedPool_<32> pool32;
  fixedPool_<128> pool128;
  fixedPool_<512> pool512;
  fixedPool_<64, 1024> pool64;
  fixedPool_<256, 1024> pool256;
};

}  // namespace simeng
