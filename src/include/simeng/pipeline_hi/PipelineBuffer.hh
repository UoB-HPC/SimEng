#pragma once

#include <algorithm>
#include <memory>
#include <vector>

namespace simeng {
namespace pipeline_hi {

/** A tickable pipelined buffer. Values are shifted from the tail slot to the
 * head slot each time `tick()` is called. */
template <class T>
class PipelineBuffer {
 public:
  /** Construct a pipeline buffer of width `width`, and fill all slots with
   * `initialValue`. */
  PipelineBuffer(int width, const T& initialValue)
      : width(width), buffer(width * defaultLength_, initialValue),
        length_(defaultLength_), headIndex_(defaultLength_-1),
        tailIndex_(0) {}

  PipelineBuffer(int width, const T& initialValue, int length)
      : width(width), buffer(width * length, initialValue), length_(length),
        headIndex_(length_-1), tailIndex_(0) {
    assert(length_ != 0 && "Pipeline buffer length cannot be 0");
  }

  /** Tick the buffer and move head/tail pointers, or do nothing if it's
   * stalled. */
  void tick() {
    if (isStalled_) return;

    //length ==1 shortcut? condition check cost

    if (headIndex_) { // when headIndex != 0
      headIndex_--;
    } else {
      headIndex_ = length_ - 1;
    }
    if (tailIndex_) { // when tailIndex != 0
      tailIndex_--;
    } else {
      tailIndex_ = length_ - 1;
    }
  }

  /** Get a tail slots pointer. */
  T* getTailSlots() {
    T* ptr = buffer.data();
    return &ptr[tailIndex_ * width];
  }

  /** Get a const tail slots pointer. */
  const T* getTailSlots() const {
    const T* ptr = buffer.data();
    return &ptr[tailIndex_ * width];
  }

  /** Get a head slots pointer. */
  T* getHeadSlots() {
    T* ptr = buffer.data();
    return &ptr[headIndex_ * width];
  }

  /** Get a const head slots pointer. */
  const T* getHeadSlots() const {
    const T* ptr = buffer.data();
    return &ptr[headIndex_ * width];
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

  /** Whether the buffer is stalled or not. */
  bool isStalled_ = false;

  /** Buffer length */
  const unsigned int length_;

  /**  */
  unsigned int headIndex_;

  /**  */
  unsigned int tailIndex_;

  /** The number of stages in the pipeline. */
  static const unsigned int defaultLength_ = 2;
};

}  // namespace pipeline_hi
}  // namespace simeng
