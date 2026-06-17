#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "framework/output.hh"

/**
 * This struct holds all information related to any
 * errors/exceptions that could happen during execution of the binary specified
 * by a TEST_GROUP. A process exception is thrown upon failure and handled
 * inside the exception handler.
 */
struct ProcessException {
  /** Custom error string specifying the type of error. */
  std::string errString_;
  /** Captured stdout of the child process. */
  std::string stderrStr_;
  /** Captured stderr of the child process. */
  std::string stdoutStr_;
  ProcessException() : errString_(""), stderrStr_(""), stdoutStr_(""){};
  ProcessException(std::string errString)
      : errString_(errString), stderrStr_(""), stdoutStr_(""){};
  ProcessException(std::string errString, std::string stderrStr,
                   std::string stdoutStr)
      : errString_(errString), stderrStr_(stderrStr), stdoutStr_(stdoutStr){};
};

/**
 * Process class responsible for creating a child process which executes
 * SST with the configuration file and CLI arguments specified by TEST_GROUP(s)
 * and TEST_CASE(s). This class also captures the stdout and stderr of the child
 * process and passes it back to the main process.
 */
class Process {
 private:
  /** Captured stdout of the child process. */
  std::string stdoutCapture_;
  /** Captured stderr of the child process.*/
  std::string stderrCapture_;
  /** Reference to the output class.*/
  Output output_;
  /** Default CLI argument specified by a TEST_GROUP. */
  std::vector<std::string> defaultCliArgs_;
  /** Path to the SST binary. */
  std::string sstBinPath_;
  /** Path to the SST config file defined by the TEST_GROUP. */
  std::string sstSimConfigFile_;
  /** Command used to invoke the SST binary. */
  std::string sstCmd_;

 public:
  Process(std::vector<std::string> args) {
#ifdef SST_TEST_CMD
    sstCmd_ = SST_TEST_CMD;
#else
    sstCmd_ = "sst";
#endif
    sstSimConfigFile_ = std::string(SST_TEST_DIR) + "/sstconfigs/" + args.at(1);
    sstBinPath_ = std::string(SST_INSTALL_DIR) + "/bin/" + sstCmd_;
    args.erase(args.begin());
    args.erase(args.begin());
    defaultCliArgs_ = args;
  };
  Process() {}

  /**
   * This method is used to run the SST executable with a config file and
   * command line arguments. This method takes in additional command line
   * arguments which replace default ones. If no additional command line
   * arguments are given the default ones are used.
   */
  void runExecAndCaptureStdout(
      std::vector<std::string> newArgs = std::vector<std::string>()) {
    stderrCapture_ = "";
    stdoutCapture_ = "";

    // variable used to capture the status of the child process.
    int status;
    // int arrays defined for stdout and stderr pipes.
    int stdout_pipes[2];
    int stderr_pipes[2];

    // Pipe syscall which converts the int arrays defined above into pipes.
    if (pipe(stdout_pipes) < 0) {
      perror("Error occured while creating stdout pipes.");
      exit(EXIT_FAILURE);
    };
    if (pipe(stderr_pipes) < 0) {
      perror("Error occured while creating stderr pipes.");
      exit(EXIT_FAILURE);
    };

    // forking into a child process.
    pid_t pid = fork();

    // If fork fails, throw exception.
    if (pid < 0) {
      perror("Could not fork process");
      exit(EXIT_FAILURE);
    }

    // If pid == 0, then we are in the forked child process.
    if (pid == 0) {
      // redirect STDOUT and STDERR to refer to the same open file descriptor
      // as stdout_pipes[1] and stderr_pipes[1] i.e anything written to STDOUT
      // and STDERR will now be redirected to the stdout and stderr pipes;
      dup2(stdout_pipes[1], STDOUT_FILENO);
      dup2(stderr_pipes[1], STDERR_FILENO);

      // Close the local copies of stdout and stderr, this needs to be done as
      // the child process doesn't have any use for them because execv will
      // replace the entire process image. STDOUT and STDERR have already been
      // redirected in the previous step.
      // For a thorough explaination see:
      // https://stackoverflow.com/questions/35447474/in-c-are-file-descriptors-that-the-child-closes-also-closed-in-the-parent

      if (close(stdout_pipes[0]) < 0) {
        perror(
            "Error occured while closing the read end of the stdout pipe in "
            "child process");
        exit(EXIT_FAILURE);
      };
      if (close(stdout_pipes[1]) < 0) {
        perror(
            "Error occured while closing the old write end of the stdout pipe "
            "in child process");
        exit(EXIT_FAILURE);
      };
      if (close(stderr_pipes[0]) < 0) {
        perror(
            "Error occured while closing the read end of the stderr pipe in "
            "child process");
        exit(EXIT_FAILURE);
      };
      if (close(stderr_pipes[1]) < 0) {
        perror(
            "Error occured while closing the old write end of the stderr pipe "
            "in child process");
        exit(EXIT_FAILURE);
      };

#ifdef SST_TESTS_MODEL_CONFIG_PATH
      std::string modelConfigPath =
          "model=" + std::string(SST_TESTS_MODEL_CONFIG_PATH);
#else
      std::string modelConfigPath = R"(model="")";
#endif
      // Execute the binary using the execv syscall. Execv doesn't return as it
      // replaces the current process image (child process) with the process
      // image of the executable. However, a return from execv indicates an
      // error in invocation of execv and not the executable.

      std::vector<std::string> argsToCpy =
          newArgs.size() ? newArgs : defaultCliArgs_;
      argsToCpy.push_back(modelConfigPath);
      // Execv calls takes in a char* path to the binary and char* argv[] array
      // for all command line arguments. To maintain consistency in parsing, the
      // structure of cliArgs mimics the invocation format of SST i.e. [sstCmd_]
      // [sstSimConfigFile] -- [cliArg1] [cliArg2] [cliArg3] for e.g:
      // {"sst","/home/a/b/c/config.py" , "--", "e", "f", "g", nullptr} Anything
      // following '--' is treated as an argument to the config.py file by SST
      // and can be used to change values in the config.py file.
      std::vector<char*> cliArgs;
      // The additional 4 entries are reserved for:
      // sstCmd_ , sstSimConfigFile, '--' and nullptr.
      // The last entry of cliArgs vector is nullptr because execv requires a
      // null terminated char* argv[].
      char* sstDelim = (char*)"--";
      cliArgs.resize(argsToCpy.size() + 4, nullptr);
      cliArgs[0] = strToCharPtr(sstCmd_);
      cliArgs[1] = strToCharPtr(sstSimConfigFile_);
      cliArgs[2] = sstDelim;
      std::transform(argsToCpy.begin(), argsToCpy.end(), cliArgs.begin() + 3,
                     [&](const std::string& str) { return strToCharPtr(str); });
      execv(sstBinPath_.c_str(), &cliArgs[0]);
      exit(EXIT_FAILURE);
    };
    if (pid > 0) {
      pid = wait(&status);
      // Close the write pipes of both stdout and stderr otherwise the read
      // function will never encounter an EOF and the while loop will never
      // terminate.
      if (close(stdout_pipes[1]) < 0) {
        std::string err = output_.strBuilder(
            " ", Formatter::bold_bright_red("Error in parent process:"),
            "Failed to close stdout output pipe.");
        throw ProcessException{err};
      }
      if (close(stderr_pipes[1]) < 0) {
        std::string err = output_.strBuilder(
            " ", Formatter::bold_bright_red("Error in parent process:"),
            "Failed to close stderr output pipe.");
        throw ProcessException{err};
      }
      std::string std_out;
      std::string std_err;
      char ch;
      // Read the redirected stdout from the stdout output pipe.
      while (read(stdout_pipes[0], &ch, 1) > 0) {
        std_out.push_back(ch);
      }
      // Read the redirected stderr from the stderr output pipe.
      while (read(stderr_pipes[0], &ch, 1) > 0) {
        std_err.push_back(ch);
      }

      // Check if child process running the executable terminated
      // successfully.
      if (!WIFEXITED(status)) {
        std::string err;
        // check if failure was caused by a segfault.
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
          err = output_.strBuilder(
              " ", Formatter::bold_bright_red("Error in executable:"),
              "Process terminated with a segfault");
        } else {
          err = output_.strBuilder(
              " ", Formatter::bold_bright_red("Error in executable:"),
              "Process terminated with an error");
        }
        throw ProcessException{err, std_err, std_out};
      }
      // Check if child process exited succesfully and status was EXIT_FAILURE.
      // Calling exit(EXIT_FAILURE) is still a successful exit albeit with a
      // failing status.
      if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE) {
        std::string err = output_.strBuilder(
            " ", Formatter::bold_bright_red("Error in executable:"),
            "Process exited with an error");
        throw ProcessException{err, std_err, std_out};
      }

      // Close the read pipes of both stdout and stderr.
      if (close(stderr_pipes[0]) < 0) {
        std::string err = output_.strBuilder(
            " ", Formatter::bold_bright_red("Error in parent process:"),
            "Failed to close stderr input pipe.");
        throw ProcessException{err};
      }
      if (close(stdout_pipes[0]) < 0) {
        std::string err = output_.strBuilder(
            " ", Formatter::bold_bright_red("Error in parent process:"),
            "Failed to close stdout input pipe.");
        throw ProcessException{err};
      }

      stdoutCapture_ = std_out;
      stderrCapture_ = std_err;
    }
  };
  /** This method converts a std::string into char*. */
  char* strToCharPtr(const std::string& str) {
    char* strd = new char[str.size() + 1];
    std::copy(str.begin(), str.end(), strd);
    strd[str.size()] = '\0';
    return strd;
  }
  /** This method returns the captured stdout of the child process. */
  std::string getStdOutCapture() { return stdoutCapture_; }
  /** This method returns the captured stderr of the child process. */
  std::string getStdErrCapture() { return stderrCapture_; }
};