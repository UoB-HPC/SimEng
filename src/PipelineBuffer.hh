#ifndef __H_PIPELINE_BUFFER
#define __H_PIPELINE_BUFFER

#include <memory>

namespace simeng {

// TODO: Extend to allow specifying the number of cycles it will take for
// information to move from tail to head (currently fixed at 1 by
// implementation)

/** A tickable pipelined buffer. Values are shifted from the tail slot to the
 * head slot each time `tick()` is called. */
template <class T>
class PipelineBuffer {
 public:
  /** Create a new pipeline buffer of width `width`. */
  PipelineBuffer(int width) : width(width) {
    // Reserve a buffer large enough to hold 2 * width elements of type `T`
    buffer = std::shared_ptr<T>(
        reinterpret_cast<T*>(malloc(sizeof(T) * width * length)), free);
  }

  /** Construct a pipeline buffer of width `width`, and fill all slots with
   * `initialValue`. */
  PipelineBuffer(int width, const T& initialValue) : PipelineBuffer(width) {
    fill(initialValue);
  }

  /** Tick the buffer and move head/tail pointers, or do nothing if it's
   * stalled. */
  void tick() {
    if (isStalled_) return;

    headIsStart = !headIsStart;
  }

  /** Get a tail slots pointer. */
  T* getTailSlots() const {
    auto ptr = buffer.get();
    return &ptr[headIsStart * width];
  }

  /** Get a head slots pointer. */
  T* getHeadSlots() const {
    auto ptr = buffer.get();
    return &ptr[!headIsStart * width];
  }

  /** Check if the buffer is stalled. */
  bool isStalled() const { return isStalled_; }

  /** Set the buffer's stall flag to `stalled`. */
  void stall(bool stalled) { isStalled_ = stalled; }

  /** Fill the buffer with a specified value. */
  void fill(const T& value) {
    auto ptr = buffer.get();
    for (size_t i = 0; i < width * length; i++) {
      ptr[i] = value;
    }
  }

 private:
  /** The width of each row of slots. */
  unsigned short width;

  /** The buffer. */
  std::shared_ptr<T> buffer;

  /** The offset of the head pointer; either 0 or 1. */
  bool headIsStart = 0;

  /** Whether the buffer is stalled or not. */
  bool isStalled_ = false;

  /** The number of stages in the pipeline. */
  static const unsigned int length = 2;
};

}  // namespace simeng

#endif
