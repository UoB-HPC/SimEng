#pragma once

#include <memory>
namespace simeng {

template <typename T>
class SubscriberInterface;

template <typename T>
class PublisherInterface {
 public:
  virtual void subscribe(std::shared_ptr<SubscriberInterface<T>> sub) = 0;
  virtual void notify(T data) = 0;
};

template <typename T>
class SubscriberInterface {
 public:
  virtual void update(T data);
};

template <typename T>
class SoloPublisher : public PublisherInterface<T> {
 protected:
  std::shared_ptr<SubscriberInterface<T>> subscriber_ = nullptr;

 private:
  virtual void subscribe(std::shared_ptr<SubscriberInterface<T>> sub) = 0;
  virtual void notify(T data) = 0;
};

}  // namespace simeng
