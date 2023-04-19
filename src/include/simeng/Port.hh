#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <type_traits>

namespace simeng {

// Type traits to check if a template parameter is a unique_ptr.
template <class T>
struct is_unique_ptr : std::false_type {};

template <class T>
struct is_unique_ptr<std::unique_ptr<T>> : std::true_type {};

// Forward declaration of the PortMediator class.
template <typename T>
class PortMediator;

/** The Port class represents an endpoint of a bidirectional connection between
 * two classes. Only one type of data can pass through a Port, this type is
 * defined by the template parameter. */
template <typename T>
class Port {
  /** Static counter variables used for assigning ids to each port. */
  static inline uint64_t idctr_ = 0;
  /** Typedef for callback function called in the recieve function. */
  using InFnType = std::function<void(T)>;

 public:
  /** Id of a port. */
  const uint64_t id_;

  /** Function used to connect a port to a port mediator. */
  void inline connect(PortMediator<T>* mediator, uint8_t order) {
    conn_ = mediator;
    order_ = order;
  };

  /** Function used to register a callback function called by the recieve
   * function. */
  void inline registerReceiver(InFnType fn) { reciever_ = fn; };

  /** Function used to send data from the source port towards the destination
   * port. */
  void inline send(T data) {
    if constexpr (is_unique_ptr<T>::value) {
      conn_->send(std::move(data), order_);
    } else {
      conn_->send(data, order_);
    }
  }

  /** Function used to recieve data from a source port. */
  void inline recieve(T data) {
    if constexpr (is_unique_ptr<T>::value) {
      reciever_(std::move(data));
    } else {
      reciever_(data);
    }
  }

  /** Function which returns the order of a port. */
  uint8_t inline getOrder() { return order_; }

  /** Constructor of the Port class. */
  Port() : id_(idctr_++) {}

 private:
  /** Order of a port used to convey the order in which the ports are connected,
   * this is used to determine the destination of each port. */
  uint8_t order_ = 0;

  /** Pointer to a PortMediator class. */
  PortMediator<T>* conn_ = nullptr;

  /** The callback function invoked in the recieve member function. */
  InFnType reciever_ = nullptr;
};

/** A PortMediator class represents a connection between two Port classes. It is
 * used to establish bidirectional communication between two Ports. The
 * PortMediator can only pass one type of data through it, this type is defined
 * by its template parameter. The template type of the PortMediator should match
 * the template type of the two connecting Ports.*/
template <typename T>
class PortMediator {
  /** Array used to store each port. */
  std::array<Port<T>*, 2> ports_;

  /** Array used to store the destination of each port. */
  std::array<Port<T>*, 2> dests_;

 public:
  /** Function used to connect two ports together. */
  void connect(Port<T>* p1, Port<T>* p2) {
    p1->connect(this, 0);
    p2->connect(this, 1);
    ports_[0] = p1;
    ports_[1] = p2;
    dests_[0] = p2;
    dests_[1] = p1;
  }

  /** Function used to send data from a port to corresponding destination port.
   */
  void inline send(T data, uint64_t port_order) {
    Port<T>* dest = dests_[port_order];
    if constexpr (is_unique_ptr<T>::value) {
      dest->recieve(std::move(data));
    } else {
      dest->recieve(data);
    }
  }
};

}  // namespace simeng