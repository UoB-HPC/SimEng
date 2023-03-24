#pragma once

#include <algorithm>
#include <memory>
#include <vector>

namespace simeng {
namespace pipeline {

// TODO: Extend to allow specifying the number of cycles it will take for
// information to move from tail to head (currently fixed at 1 by
// implementation)

/** A tickable pipelined buffer. Values are shifted from the tail slot to the
 * head slot each time `tick()` is called. */
template <class T>
class PipelineBuffer {
 public:
  /** Construct a pipeline buffer of width `width`, and fill all slots with
   * `initialValue`. */
  PipelineBuffer(int width, const T& initialValue)
      : width(width), buffer(width * length, initialValue) {}

  /** Tick the buffer and move head/tail pointers, or do nothing if it's
   * stalled. */
  void tick() {
    if (isStalled_) return;

    headIsStart = !headIsStart;
  }

  const T* getPendingSlots() const {
    if (isStalled_) {
      return getTailSlots();
    } else {
      return getHeadSlots();
    }
  }

  /** Get a tail slots pointer. */
  T* getTailSlots() {
    T* ptr = buffer.data();
    return &ptr[headIsStart * width];
  }
  /** Get a const tail slots pointer. */
  const T* getTailSlots() const {
    const T* ptr = buffer.data();
    return &ptr[headIsStart * width];
  }

  /** Get a head slots pointer. */
  T* getHeadSlots() {
    T* ptr = buffer.data();
    return &ptr[!headIsStart * width];
  }
  /** Get a const head slots pointer. */
  const T* getHeadSlots() const {
    const T* ptr = buffer.data();
    return &ptr[!headIsStart * width];
  }

  /** Check if the buffer is stalled. */
  bool isStalled() const { return isStalled_; }

  /** Set the buffer's stall flag to `stalled`. */
  void stall(bool stalled) { isStalled_ = stalled; }

  /** Fill the buffer with a specified value. */
  void fill(const T& value) { std::fill(buffer.begin(), buffer.end(), value); }

  /** Get the width of the buffer slots. */
  unsigned short getWidth() const { return width; }

 private:
  /** The width of each row of slots. */
  unsigned short width;

  /** The buffer. */
  std::vector<T> buffer;

  /** The offset of the head pointer; either 0 or 1. */
  bool headIsStart = 0;

  /** Whether the buffer is stalled or not. */
  bool isStalled_ = false;

  /** The number of stages in the pipeline. */
  static const unsigned int length = 2;
};

}  // namespace pipeline
}  // namespace simeng
