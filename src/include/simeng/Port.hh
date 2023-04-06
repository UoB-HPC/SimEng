#pragma once

#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <type_traits>

namespace simeng {

template <class T>
struct is_unique_ptr : std::false_type {};

template <class T>
struct is_unique_ptr<std::unique_ptr<T>> : std::true_type {};

template <typename T>
class PortMediator;

template <typename T>
struct Port {
  static inline uint64_t idctr_ = 0;
  using InFnType = std::function<void(T)>;

 public:
  const uint64_t id_;

  void connect(PortMediator<T>* mediator, uint8_t order) {
    conn_ = mediator;
    order_ = order;
  };

  void registerReceiver(InFnType fn) { reciever_ = fn; };

  void send(T data) {
    if constexpr (is_unique_ptr<T>::value) {
      conn_->send(std::move(data), order_);
    } else {
      conn_->send(data, order_);
    }
  }

  void recieve(T data) {
    if constexpr (is_unique_ptr<T>::value) {
      reciever_(std::move(data));
    } else {
      reciever_(data);
    }
  }

  uint8_t inline getOrder() { return order_; }

  Port() : id_(idctr_++) {}

 private:
  uint8_t order_ = 0;
  PortMediator<T>* conn_ = nullptr;
  InFnType reciever_ = nullptr;
};

template <typename T>
class PortMediator {
  std::array<Port<T>*, 2> ports_;
  std::array<Port<T>*, 2> dests_;

 public:
  void connect(Port<T>* p1, Port<T>* p2) {
    p1->connect(this, 0);
    p2->connect(this, 1);
    ports_[0] = p1;
    ports_[1] = p2;
    dests_[0] = p2;
    dests_[1] = p1;
  }
  void send(T data, uint64_t port_order) {
    Port<T>* dest = dests_[port_order];
    if constexpr (is_unique_ptr<T>::value) {
      dest->recieve(std::move(data));
    } else {
      dest->recieve(data);
    }
  }
};

}  // namespace simeng
