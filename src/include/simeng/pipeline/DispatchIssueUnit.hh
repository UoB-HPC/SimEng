#pragma once

#include <deque>
#include <initializer_list>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include "simeng/Instruction.hh"
#include "simeng/OperandBypassMap.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** A reservation station issue port */
struct ReservationStationPort {
  /** Issue port this port maps to */
  uint16_t issuePort;
  /** Queue of instructions that are ready to be
   * issued */
  std::deque<std::shared_ptr<Instruction>> ready;
};

/** A reservation station */
struct ReservationStation {
  /** Size of reservation station */
  uint16_t capacity;
  /** Number of instructions that can be dispatched to this unit per cycle. */
  uint16_t dispatchRate;
  /** Current number of non-stalled instructions
   * in reservation station */
  uint16_t currentSize;
  /** Issue ports belonging to reservation station */
  std::vector<ReservationStationPort> ports;
};

/** An entry in the dependancy structures. */
struct dependencyEntry {
  /** The instruction to execute. */
  std::shared_ptr<Instruction> uop;
  /** The port to issue to. */
  uint16_t port;
  /** The operand waiting on a value. */
  uint16_t operandIndex;
};

/** A dispatch/issue unit for an out-of-order pipelined processor. Reads
 * instruction operand and performs scoreboarding. Issues instructions to the
 * execution unit once ready. */
class DispatchIssueUnit {
 public:
  /** Construct a dispatch/issue unit with references to input/output buffers,
   * the register file, the port allocator, and a description of the number of
   * physical registers the scoreboard needs to reflect. */
  DispatchIssueUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
      std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
      const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
      OperandBypassMap& bypassMap,
      const std::vector<uint16_t>& physicalRegisterStructure);

  /** Ticks the dispatch/issue unit. Reads available input operands for
   * instructions and sets scoreboard flags for destination registers. */
  void tick();

  /** Identify the oldest ready instruction in the reservation station and issue
   * it. */
  void issue();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values,
                       const uint16_t producerGroup);

  /** Set the scoreboard entry for the provided register as ready. */
  void setRegisterReady(Register reg);

  /** Clear the RS of all flushed instructions. */
  void purgeFlushed();

  /** Flush scoreboard, dependancyMatrix. Primarily used for context
   * switching. */
  void flush();

  /** Retrieve the number of cycles this unit stalled due to insufficient RS
   * space. */
  uint64_t getRSStalls() const;
  std::vector<uint64_t> getRSStallsPort() const;

  /** Retrieve the number of cycles no instructions were issued due to an empty
   * RS. */
  uint64_t getFrontendStalls() const;
  std::vector<uint64_t> getFrontendStallsPort() const;

  /** Retrieve the number of cycles no instructions were issued due to
   * dependencies or a lack of available ports. */
  uint64_t getBackendStalls() const;
  std::vector<uint64_t> getBackendStallsPort() const;

  /** Retrieve the number of times an instruction was unable to issue due to a
   * busy port. */
  uint64_t getPortBusyStalls() const;

  /** Retrieve the current sizes and capacities of the reservation stations*/
  void getRSSizes(std::vector<uint64_t>&) const;

  /** Flags the associated slot in the scoreboard as ready. */
  void updateScoreboard(const Register& reg);

  const std::vector<uint64_t> getPossibleIssues() const;

  const std::vector<uint64_t> getActualIssues() const;

  void resetStats();

 private:
  /** A buffer of instructions to dispatch and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** Ports to the execution units, for writing ready instructions to. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts_;

  /** A reference to the physical register file set. */
  const RegisterFileSet& registerFileSet_;

  /** The register availability scoreboard. */
  std::vector<std::vector<bool>> scoreboard_;

  /** Reservation stations */
  std::vector<ReservationStation> reservationStations_;

  /** A mapping from port to RS port */
  std::vector<std::pair<uint16_t, uint16_t>> portMapping_;

  /** A dependency matrix, containing all the instructions waiting on an
   * operand. For a register `{type,tag}`, the vector of dependents may be found
   * at `dependencyMatrix[type][tag]`. */
  std::vector<std::vector<std::vector<dependencyEntry>>> dependencyMatrix_;

  /** Contains all of the instructions that have a dependency with another
   * instruction, but is not permitted to have the result forwarded to them
   * directly. */
  std::vector<dependencyEntry> dependantInstructions_;

  /** Contains instructions that have had results forwarded to them, but need to
   * wait for x-cycles to mimic the in hardware latency of said result
   * forwarding.
   * Key = Tick count to release instruction on.
   * Value = Vector of pairs<Instruction entry, value forwarded to it>. */
  std::unordered_map<uint64_t,
                     std::vector<std::pair<dependencyEntry, RegisterValue>>>
      waitingInstructions_;

  /** A map to collect flushed instructions for each reservation station. */
  std::unordered_map<uint16_t, std::unordered_set<std::shared_ptr<Instruction>>>
      flushed_;

  /** Records the number of instructions dispatched for each reservation station
   * within a cycle. */
  std::unique_ptr<uint16_t[]> dispatches_;

  /** A reference to the execution port allocator. */
  PortAllocator& portAllocator_;

  /** A reference to the operand bypass map. */
  OperandBypassMap& operandBypassMap_;

  /** The number of cycles stalled due to a full reservation station. */
  uint64_t rsStalls_ = 0;
  std::vector<uint64_t> rsStallsPort_;

  /** The number of cycles no instructions were issued due to an empty RS. */
  uint64_t frontendStalls_ = 0;
  std::vector<uint64_t> frontendStallsPort_;

  /** The number of cycles no instructions were issued due to dependencies or a
   * lack of available ports. */
  uint64_t backendStalls_ = 0;
  std::vector<uint64_t> backendStallsPort_;

  /** The number of times an instruction was unable to issue due to a busy port.
   */
  uint64_t portBusyStalls_ = 0;

  /** The number of ticks elapsed so far. */
  uint64_t ticks_ = 0;

  std::vector<uint64_t> possibleIssues_;

  std::vector<uint64_t> actualIssues_;

  std::vector<std::string> portNames_ = {"FLA", "PR",   "EXA", "FLB",
                                         "EXB", "EAGA", "EAGB"};

  std::vector<std::string> groupOptions_ = {"INT",
                                            "INT_SIMPLE",
                                            "INT_SIMPLE_ARTH",
                                            "INT_SIMPLE_ARTH_NOSHIFT",
                                            "INT_SIMPLE_LOGICAL",
                                            "INT_SIMPLE_LOGICAL_NOSHIFT",
                                            "INT_SIMPLE_CMP",
                                            "INT_SIMPLE_CVT",
                                            "INT_MUL",
                                            "INT_DIV_OR_SQRT",
                                            "LOAD_INT",
                                            "STORE_ADDRESS_INT",
                                            "STORE_DATA_INT",
                                            "STORE_INT",
                                            "FP",
                                            "FP_SIMPLE",
                                            "FP_SIMPLE_ARTH",
                                            "FP_SIMPLE_ARTH_NOSHIFT",
                                            "FP_SIMPLE_LOGICAL",
                                            "FP_SIMPLE_LOGICAL_NOSHIFT",
                                            "FP_SIMPLE_CMP",
                                            "FP_SIMPLE_CVT",
                                            "FP_MUL",
                                            "FP_DIV_OR_SQRT",
                                            "SCALAR",
                                            "SCALAR_SIMPLE",
                                            "SCALAR_SIMPLE_ARTH",
                                            "SCALAR_SIMPLE_ARTH_NOSHIFT",
                                            "SCALAR_SIMPLE_LOGICAL",
                                            "SCALAR_SIMPLE_LOGICAL_NOSHIFT",
                                            "SCALAR_SIMPLE_CMP",
                                            "SCALAR_SIMPLE_CVT",
                                            "SCALAR_MUL",
                                            "SCALAR_DIV_OR_SQRT",
                                            "LOAD_SCALAR",
                                            "STORE_ADDRESS_SCALAR",
                                            "STORE_DATA_SCALAR",
                                            "STORE_SCALAR",
                                            "VECTOR",
                                            "VECTOR_SIMPLE",
                                            "VECTOR_SIMPLE_ARTH",
                                            "VECTOR_SIMPLE_ARTH_NOSHIFT",
                                            "VECTOR_SIMPLE_LOGICAL",
                                            "VECTOR_SIMPLE_LOGICAL_NOSHIFT",
                                            "VECTOR_SIMPLE_CMP",
                                            "VECTOR_SIMPLE_CVT",
                                            "VECTOR_MUL",
                                            "VECTOR_DIV_OR_SQRT",
                                            "LOAD_VECTOR",
                                            "STORE_ADDRESS_VECTOR",
                                            "STORE_DATA_VECTOR",
                                            "STORE_VECTOR",
                                            "SVE",
                                            "SVE_SIMPLE",
                                            "SVE_SIMPLE_ARTH",
                                            "SVE_SIMPLE_ARTH_NOSHIFT",
                                            "SVE_SIMPLE_LOGICAL",
                                            "SVE_SIMPLE_LOGICAL_NOSHIFT",
                                            "SVE_SIMPLE_CMP",
                                            "SVE_SIMPLE_CVT",
                                            "SVE_MUL",
                                            "SVE_DIV_OR_SQRT",
                                            "LOAD_SVE",
                                            "STORE_ADDRESS_SVE",
                                            "STORE_DATA_SVE",
                                            "STORE_SVE",
                                            "PREDICATE",
                                            "LOAD",
                                            "STORE_ADDRESS",
                                            "STORE_DATA",
                                            "STORE",
                                            "BRANCH",
                                            "SME",
                                            "SME_SIMPLE",
                                            "SME_SIMPLE_ARTH",
                                            "SME_SIMPLE_ARTH_NOSHIFT",
                                            "SME_SIMPLE_LOGICAL",
                                            "SME_SIMPLE_LOGICAL_NOSHIFT",
                                            "SME_SIMPLE_CMP",
                                            "SME_SIMPLE_CVT",
                                            "SME_MUL",
                                            "SME_DIV_OR_SQRT",
                                            "LOAD_SME",
                                            "STORE_ADDRESS_SME",
                                            "STORE_DATA_SME",
                                            "STORE_SME",
                                            "ALL",
                                            "NONE"};
};

}  // namespace pipeline
}  // namespace simeng
