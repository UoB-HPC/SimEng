#pragma once

#include <algorithm>
#include <memory>
#include <vector>

namespace simeng {
namespace pipeline_hi {

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
      : width(width), buffer(width * defaultLength_, initialValue),
        length_(defaultLength_) {}

  //TODO:currently length > 2 is not working, oscillate between 0 and 1
  PipelineBuffer(int width, const T& initialValue, int length)
      : width(width), buffer(width * length, initialValue), length_(length),
        useDefaultLength_(false) {
    assert(length_ != 0 && "Pipeline buffer length cannot be 0");
  }

  /** Tick the buffer and move head/tail pointers, or do nothing if it's
   * stalled. */
  void tick() {
    if (useDefaultLength_) {
      if (isStalled_) return;

      headIsStart = !headIsStart;
    } else {
      if (length_ == 1) {
        return;
      } else if (length_ > 2) {
        //TODO
      }
    }
  }

  /** Get a tail slots pointer. */
  T* getTailSlots() {
    T* ptr = buffer.data();
    if (useDefaultLength_) {
      return &ptr[headIsStart * width];
    } else {
      if (length_ == 1) {
        return &ptr[0];
      }
    }
  }

  /** Get a const tail slots pointer. */
  const T* getTailSlots() const {
    const T* ptr = buffer.data();
    if (useDefaultLength_) {
      return &ptr[headIsStart * width];
    } else {
      if (length_ == 1) {
        return &ptr[0];
      }
    }
  }


      /** Get a head slots pointer. */
  T* getHeadSlots() {
    T* ptr = buffer.data();
    if (useDefaultLength_) {
      return &ptr[!headIsStart * width];
    } else {
      if (length_ == 1) {
        return &ptr[0];
      }
    }
  }

  /** Get a const head slots pointer. */
  const T* getHeadSlots() const {
    const T* ptr = buffer.data();
    if (useDefaultLength_) {
      return &ptr[!headIsStart * width];
    } else {
      if (length_ == 1) {
        return &ptr[0];
      }
    }
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

  /** Buffer length */
  const unsigned int length_;

  /** True if using default length (== 2) */
  bool useDefaultLength_ = true;

  /** The number of stages in the pipeline. */
  static const unsigned int defaultLength_ = 2;
};

}  // namespace pipeline_hi
}  // namespace simeng
