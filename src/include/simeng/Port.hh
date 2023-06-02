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

/** The Port class represents an endpoint of a bidirectional connection between
 * two classes. Only one type of data can pass through a Port, this type is
 * defined by the template parameter. */
template <typename T>
class Port {
  /** Static counter variables used for assigning ids to each port. */
  static inline uint64_t idctr_ = 0;
  /** Typedef for callback function called in the recieve function. */
  using InFnType = std::function<void(T)>;

  /***/
  using OutFnType = std::function<void(T, uint16_t)>;

 public:
  /** Function used to connect a port to a port mediator. */
  void inline connect(OutFnType fn, uint16_t id) {
    sendToDestination = fn;
    id_ = id;
  };

  /** Function used to register a callback function called by the recieve
   * function. */
  void inline registerReceiver(InFnType fn) { reciever_ = fn; };

  /** Function used to send data from the source port towards the destination
   * port. */
  void inline send(T data) {
    if constexpr (is_unique_ptr<T>::value) {
      sendToDestination(std::move(data), id_);
    } else {
      sendToDestination(data, id_);
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

  uint16_t getId() { return id_; }

  /** Constructor of the Port class. */
  Port() {}

 private:
  /** The ID of a port. Used by a mediator connection to locate the destination
   * port of the corresponding source port. */
  uint16_t id_;

  /***/
  OutFnType sendToDestination;

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
  std::array<std::shared_ptr<Port<T>>, 2> ports_;

  /** Array used to store the destination of each port. */
  std::array<std::shared_ptr<Port<T>>, 2> dests_;

 public:
  /** Function used to connect two ports together. */
  void connect(std::shared_ptr<Port<T>> p1, std::shared_ptr<Port<T>> p2) {
    auto fn = [this](T data, uint16_t port_id) -> void {
      if constexpr (is_unique_ptr<T>::value) {
        send(std::move(data), port_id);
      } else {
        send(data, port_id);
      }
    };
    p1->connect(fn, 0);
    p2->connect(fn, 1);
    ports_[0] = p1;
    ports_[1] = p2;
    dests_[0] = p2;
    dests_[1] = p1;
  }

  /** Function used to send data from a port to corresponding destination port.
   */
  void inline send(T data, uint64_t port_id) {
    auto dest = dests_[port_id];
    if constexpr (is_unique_ptr<T>::value) {
      dest->recieve(std::move(data));
    } else {
      dest->recieve(data);
    }
  }
};

template <typename A, typename B>
class ConvertingPortMediator {
  using FnConvertAToB = std::function<B(A)>;
  using FnConvertBToA = std::function<A(B)>;

 public:
  /** Function used to connect two ports together. */
  void connect(std::shared_ptr<Port<A>> p1, std::shared_ptr<Port<B>> p2) {
    portA_ = p1;
    portB_ = p2;

    auto fnA = [this](A arg) -> void {
      if constexpr (is_unique_ptr<A>::value) {
        send(std::move(arg), 0);
      } else {
        send(arg, 0);
      }
    };

    auto fnB = [this](B arg) -> void {
      if constexpr (is_unique_ptr<B>::value) {
        send(std::move(arg), 0);
      } else {
        send(arg, 0);
      }
    };

    portA_->connect(fnA, 0);
    portB_->connect(fnB, 0);
  };

  void send(A data, uint16_t port_id) {
    if constexpr (is_unique_ptr<A>::value && is_unique_ptr<B>::value) {
      portB_->recieve(std::move(fnA2B_(std::move(data))));
    } else if constexpr (is_unique_ptr<A>::value) {
      portB_->recieve(fnA2B_(std::move(data)));
    } else if constexpr (is_unique_ptr<B>::value) {
      portB_->recieve(std::move(fnA2B_(data)));
    } else {
      portB_->recieve(fnA2B_(data));
    }
  }

  void send(B data, uint16_t port_id) {
    if constexpr (is_unique_ptr<A>::value && is_unique_ptr<B>::value) {
      portA_->recieve(std::move(fnB2A_(std::move(data))));
    } else if constexpr (is_unique_ptr<B>::value) {
      portA_->recieve(fnB2A_(std::move(data)));
    } else if constexpr (is_unique_ptr<A>::value) {
      portA_->recieve(std::move(fnB2A_(data)));
    } else {
      portA_->recieve(fnB2A_(data));
    }
  }

  void registerConverters(FnConvertAToB fnA2B, FnConvertBToA fnB2A) {
    fnA2B_ = fnA2B;
    fnB2A_ = fnB2A;
  }

 private:
  std::shared_ptr<Port<A>> portA_ = nullptr;
  std::shared_ptr<Port<B>> portB_ = nullptr;

  FnConvertAToB fnA2B_;
  FnConvertBToA fnB2A_;
};

}  // namespace simeng
