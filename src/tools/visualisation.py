import curses
import math
import string
import argparse
import os
import datetime
from array import array
# import heartrate; heartrate.trace(browser=True)

# Constants
trace_stages = []
probe_colour_mapping = ["e", "h", "s", "b", "f"]
probe_titles = [("Stalled.fetch.instructionFetch", "s"),
                ("Stalled.fetch.instructionDecode", "s"),
                ("Stalled.rename.robFull", "s"), ("Stalled.rename.lsqFull",
                                                  "s"),
                ("Stalled.rename.sqFull", "s"),
                ("Stalled.rename.allocation", "s"),
                ("Stalled.dispatch.rsFull", "s"),
                ("Stalled.issue.portBusy", "s"),
                ("Stalled.issue.rsEmpty", "s"),
                ("Stalled.execute.instructionExecuting", "s"),
                ("Stalled.fixedLatencyMemoryUnready", "s"),
                ("Stalled.loadStoreQueue.notReady", "s"),
                ("Branch.fetch.stalled", "b"),
                ("Branch.decode.earlyMisprediction", "b"),
                ("Branch.execute.misprediction", "b"),
                ("Flush.rob.storeViolation", "f"),
                ("Halt.fetch.programMemoryExceeded", "h"),
                ("Exception.rob.robCommit", "e"),
                ("Exception.execute.beforeExecution", "e"),
                ("Exception.execute.afterExecution", "e"),
                ("Exception.flatMemoryRead", "e"),
                ("Exception.fixedLatencyMemoryRead", "e")]
# Lists
trace_data = []
probe_data = [[]]
selected_probes = len(probe_titles) * [1]
info_seperations = [0, 0, 0, 0]
# Dimension Variables
top = 0
bottom = 0
width_left = 0
# Lengths
probes_active = 0
trace_file_length = 0
probe_file_length = 0


class Window:
    def __init__(self, rows, cols, y_loc, x_loc, titles):
        global info_seperations
        self.rows = rows
        self.cols = cols
        self.titles = titles
        self.win = curses.newwin(rows, cols, y_loc, x_loc)
        self.win.border(0, 0, 0, 0, 0, 0, 0, 0)
        # Write titles
        for i in range(0, len(self.titles)):
            length = info_seperations[i] + len(self.titles[i])
            # Cutt off titles if too long for window
            if (length < self.cols):
                self.win.addstr(0, info_seperations[i], self.titles[i])
            else:
                self.win.addstr(0, self.cols - 3, "...")
        self.win.noutrefresh()

    def reset_resize(self, rows, cols, y_loc, x_loc):
        global info_seperations
        self.rows = rows
        self.cols = cols
        self.win.erase()
        self.win.resize(rows, cols)
        self.win.border(0, 0, 0, 0, 0, 0, 0, 0)
        self.win.mvwin(y_loc, x_loc)
        # Write titles
        for i in range(0, len(self.titles)):
            length = info_seperations[i] + len(self.titles[i])
            # Cutt off titles if too long for window
            if (length < self.cols):
                self.win.addstr(0, info_seperations[i], self.titles[i])
            else:
                self.win.addstr(0, self.cols - 3, "...")
        self.win.noutrefresh()

    def reset(self):
        global info_seperations
        self.win.erase()
        self.win.border(0, 0, 0, 0, 0, 0, 0, 0)
        # Write titles
        for i in range(0, len(self.titles)):
            length = info_seperations[i] + len(self.titles[i])
            # Cutt off title if too long for window
            if (length < self.cols):
                self.win.addstr(0, info_seperations[i], self.titles[i])
            else:
                self.win.addstr(0, self.cols - 3, "...")
        self.win.noutrefresh()


class Pad:
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        self.rows = rows
        self.cols = cols
        self.start_y_loc = start_y_loc
        self.start_x_loc = start_x_loc
        self.end_y_loc = end_y_loc
        self.end_x_loc = end_x_loc
        self.y_pos = y_pos
        self.x_pos = x_pos
        self.pad = curses.newpad(rows, cols)

    def reset_resize(self, rows, cols, start_y_loc, start_x_loc, end_y_loc,
                     end_x_loc):
        self.pad.erase()
        self.pad.resize(rows, cols)
        self.rows = rows
        self.cols = cols
        self.start_y_loc = start_y_loc
        self.start_x_loc = start_x_loc
        self.end_y_loc = end_y_loc
        self.end_x_loc = end_x_loc

    def reset(self):
        self.pad.erase()

    def refresh(self):
        self.pad.noutrefresh(self.y_pos, self.x_pos, self.start_y_loc,
                             self.start_x_loc, self.end_y_loc, self.end_x_loc)

    def redraw(self, view_width, width):
        # Set x position to deal with resizing of window
        if (view_width < width):
            if (self.x_pos + view_width) > width:
                self.x_pos -= (self.x_pos + view_width - width)
        else:
            self.x_pos = 0

        self.pad.noutrefresh(self.y_pos, self.x_pos, self.start_y_loc,
                             self.start_x_loc, self.end_y_loc, self.end_x_loc)


class TracePad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, first_index, last_index, view_width):
        global trace_data
        global width_left
        # Set indexing variables
        index_y = 0
        index_x = 0
        firstCycle = trace_data[first_index][0]
        current_colour = 0

        for i in range(first_index, last_index):
            # Draw flushed line
            if (trace_data[i][3]):
                self.pad.hline(index_y, 0, ord('='), self.cols)
            else:
                self.pad.hline(index_y, 0, ord('-'), self.cols)
            index_x = trace_data[i][0] - firstCycle
            for ch in trace_data[i][1]:
                # Switch colours between pipeline stages
                if (ch != '.'):
                    current_colour = (trace_stages.index(ch) + 1) % 8
                self.pad.addstr(index_y, index_x, ch,
                                curses.color_pair(current_colour))
                index_x += 1
            current_colour = 0
            index_y += 1
        super().redraw(view_width, width_left)


class ProbePad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, trace_index, view_width):
        # Set indexing variables
        first_index = trace_data[trace_index][0]
        index_y = 0
        index_x = 0
        # Print probe data by character to achieve correct colouring
        if not probes_active:
            self.pad.addstr(index_y, 0, "-" * (width_left + 1))
        else:
            for i in range(first_index - 1, first_index + self.cols - 1):
                for j in range(0, len(probe_titles)):
                    if (selected_probes[j]):
                        if (probe_data[i][0][j] == "-"):
                            # For probes that don't occur in the cycle
                            self.pad.addstr(index_y, index_x, "-",
                                            curses.color_pair(0))
                        elif (probe_data[i][0][j] == "1"):
                            # For probes that occur once in the cycle
                            colour = probe_colour_mapping.index(
                                probe_titles[j][1]) + 1
                            self.pad.addstr(index_y, index_x, " ",
                                            curses.color_pair(colour))
                        elif (probe_data[i][0][j] != "."):
                            # For probes that occur mutliple times in the cycle
                            colour = probe_colour_mapping.index(
                                probe_titles[j][1]) + 1
                            self.pad.addstr(index_y, index_x,
                                            probe_data[i][0][j],
                                            curses.color_pair(colour))
                        index_y += 1
                index_x += 1
                index_y = 0
        super().redraw(view_width, width_left)


class InfoPad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, first_index, last_index, view_width):
        global trace_data
        global info_seperations
        # Set indexing variables
        index_y = 0
        width = 0
        # Display instruction information
        for i in range(first_index, last_index):
            if len(trace_data[i][2]) > width:
                width = len(trace_data[i][2])
                if (width >= self.cols):
                    self.cols = width + 1
                    self.pad.resize(self.rows, self.cols)
            self.pad.addstr(index_y, 0, trace_data[i][2])
            index_y += 1
        super().redraw(view_width, width)


class TitlePad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, view_width):
        # Set indexing variables
        index_y = 0
        width = 0
        # Display selected probes titles
        if not probes_active:
            self.pad.addstr(index_y, 0, "No probes selected")
        else:
            for i in range(0, len(probe_titles)):
                if (selected_probes[i]):
                    title = probe_titles[i][0]
                    if len(title) > width:
                        width = len(title)
                        if (width >= self.cols):
                            self.cols = width + 1
                            self.pad.resize(self.rows, self.cols)
                    self.pad.addstr(index_y, 0, title)
                    index_y += 1
        super().redraw(view_width, width)


class SelectionPad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, view_width, select_index):
        # Set indexing variables
        index_y = 0
        width = 0
        # Display probes title selection
        for i in range(0, len(probe_titles)):
            title = probe_titles[i][0]
            line = ""
            # Print selection icon
            if (selected_probes[i]):
                line = "[ X ]"
            else:
                line = "[   ]"
            if (select_index == index_y):
                self.pad.addstr(index_y, 0, line, curses.color_pair(2))
            else:
                self.pad.addstr(index_y, 0, line)
            # Print probe title
            line = " - " + title
            if len(line) + 5 > width:
                width = len(line) + 5
                if (width >= self.cols):
                    self.cols = width + 1
                    self.pad.resize(self.rows, self.cols)
            self.pad.addstr(index_y, 5, line)
            index_y += 1
        super().redraw(view_width, width)


class AssociatedPad(Pad):
    def __init__(self, rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                 end_y_loc, end_x_loc):
        super().__init__(rows, cols, y_pos, x_pos, start_y_loc, start_x_loc,
                         end_y_loc, end_x_loc)

    def redraw(self, trace_index, view_width):
        global width_left
        # Set indexing variables
        width = 0
        first_index = trace_data[trace_index][0]
        index_y = 0
        if not probes_active:
            self.pad.addstr(index_y, 0, "No probes selected")
        else:
            asct_insn_string = [""] * len(probe_titles)
            # Collate set of instructions associated to probes in current view
            for i in range(first_index - 1, first_index + width_left):
                insn_nums = probe_data[i][1].split(':')
                for j in range(0, len(probe_titles)):
                    if (selected_probes[j]):
                        if (insn_nums[j] != "0"):
                            for num in insn_nums[j].split(','):
                                if (len(asct_insn_string[j]) > 0):
                                    asct_insn_string[j] += ", "
                                asct_insn_string[j] += num
            # Fill in selected probes with no associated instructions
            for str_index in range(0, len(asct_insn_string)):
                if (asct_insn_string[str_index] == ""):
                    asct_insn_string[str_index] = "-"
            # Print associated instructions
            for j in range(0, len(probe_titles)):
                if (selected_probes[j]):
                    if (len(asct_insn_string[j]) > width):
                        width = len(asct_insn_string[j])
                    if (width >= self.cols):
                        self.cols = width + 1
                        self.pad.resize(self.rows, self.cols)
                    self.pad.addstr(index_y, 0, asct_insn_string[j],
                                    curses.color_pair(0))
                    index_y += 1
            index_y = 0
        super().redraw(view_width, width)


def cacheLineOffsets(file, force, type):

    global trace_file_length
    global probe_file_length
    # Generate path of cache file
    filepath, ext = os.path.splitext(file)
    cache_filepath = filepath + ".cache"
    line_offsets = array("L")
    # Read in binary to include line endings in offset calculation
    if os.path.exists(cache_filepath) and (not force):
        # Read
        num_file_items = int(
            os.path.getsize(cache_filepath) / line_offsets.itemsize)
        with open(cache_filepath, 'rb') as cache:
            if (type == "trace"):
                trace_file_length = num_file_items
            elif (type == "probe"):
                probe_file_length = num_file_items
            line_offsets.fromfile(cache, num_file_items)
            cache.close()
    else:
        # Write
        with open(file, 'rb') as input:
            current_offset = 0
            if (type == "trace"):
                print("Caching bytes per line for trace file...")
                for line in input:
                    trace_file_length += 1
                    line_offsets.append(current_offset)
                    current_offset += len(line)
            elif (type == "probe"):
                print("Caching bytes per line for probe file...")
                for line in input:
                    probe_file_length += 1
                    line_offsets.append(current_offset)
                    current_offset += len(line)
            else:
                # Default case
                for line in input:
                    line_offsets.append(current_offset)
                    current_offset += len(line)
            with open(cache_filepath, 'wb') as cache:
                line_offsets.tofile(cache)
                cache.close()
            input.close()
    return line_offsets


def readTrace(file, index):
    global trace_stages
    global trace_data
    global top
    global width_left
    # Set file iterator to correct position
    if (index < len(trace_line_offsets)):
        file.seek(trace_line_offsets[index])
    else:
        file.seek(0, 2)
    # Check if entry doesn't exists in trace_data
    line_existance = (trace_data[index]
                      == (0, "", "", 0)) if index < len(trace_data) else False
    if (line_existance):
        # Get the stages cycles
        stages = []
        entries = []
        line = file.readline()
        # Ensure we haven't reached the eof
        if (line != ''):
            num_stages = len(trace_stages)
            stages = list(map(lambda x: int(x), line.split(':')[0:num_stages]))
            entries.append(line.split(':'))
            # Convert data into string
            trace_string = ""
            if (num_stages == 1):
                trace_string += trace_stages[0]
            else:
                trace_string += trace_stages[0] + (
                    (stages[1] - stages[0] - 1) * ".")
                for i in range(1, num_stages - 1):
                    if (stages[i] != 0):
                        # If two stages occur on the same cycle, display former
                        if (stages[i] == stages[i + 1]):
                            continue
                        trace_string += trace_stages[i] + (
                            (stages[i + 1] - stages[i] - 1) * ".")
                    else:
                        break
            # Dynamically space out instruction data
            info_string = ""
            num_sep = " "
            info_string += num_sep + entries[0][num_stages + 2]
            cyc_sep = (info_seperations[1] - len(info_string)) * " "
            info_string += cyc_sep + entries[0][0]
            pc_sep = (info_seperations[2] - len(info_string)) * " "
            info_string += pc_sep + entries[0][num_stages]
            dis_sep = (info_seperations[3] - len(info_string)) * " "
            info_string += dis_sep + entries[0][num_stages + 3].rstrip()
            # Determine whether instruction has been flushed
            flushed = 0
            if (stages[num_stages - 1] != 0):
                trace_string += trace_stages[-1]
            else:
                flushed = 1
            # Change entry in trace_data
            trace_data[index] = (stages[0], trace_string, info_string, flushed)
        else:
            index = -1

    # Recalculate if column width needs to change
    first_cycle = trace_data[top][0]
    length = (trace_data[index][0] - first_cycle) + len(trace_data[index][1])
    if (length > width_left):
        # Minimum column width
        if (length < 9):
            length = 9
        width_left = length


def readProbe(file, index):
    global probe_data
    # Set file iterator to correct position
    if (index < len(probe_line_offsets)):
        file.seek(probe_line_offsets[index])
    else:
        file.seek(0, 2)
    line_existance = (probe_data[index][0][0]
                      == ".") if index <= probe_file_length else False
    if (line_existance):
        line = file.readline()
        if (line == '-\n'):
            # If no probes occured on this cycle
            probe_data[index] = ("-" * len(probe_titles), probe_data[index][1])
        elif (line != ''):
            chosen = len(probe_titles) * [0]
            # Split line into seperated data
            data = line.split(':')
            for probe in data:
                # Extract index and associated instruction
                probe_split = probe.split(',')
                probe_index = int(probe_split[0])
                insn_num = int(probe_split[1].rstrip())
                # Increase number of this type of probe in this cycle
                chosen[probe_index] += 1
                # If the number of occuring probes is greater than 9 (single digit)
                insertion = str(
                    chosen[probe_index]) if chosen[probe_index] < 10 else "+"
                # Change print string to include occurance of probe
                probe_string = "".join(
                    (probe_data[index][0][:probe_index], insertion,
                     probe_data[index][0][probe_index + 1:]))
                # Change associate instruction string to include the associate instruction
                asct_insn_list = probe_data[index][1].split(':')
                if (asct_insn_list[probe_index] == "0"):
                    asct_insn_list[probe_index] = str(insn_num)
                else:
                    # If multiple of this type of probe has occured in this cycle
                    asct_insn_list[probe_index] += ","
                    asct_insn_list[probe_index] += str(insn_num)
                probe_data[index] = (probe_string, ":".join(asct_insn_list))
            probe_data[index] = (probe_data[index][0].replace('.', '-'),
                                 probe_data[index][1])
        elif (line == ''):
            # If we have reached eof add default case
            placeholder = ""
            if (len(probe_titles) > 0):
                placeholder += "0"
            for i in range(1, len(probe_titles)):
                placeholder += ":0"
            probe_data[index] = (('-' * len(probe_titles), placeholder))
    else:
        # If index is beyond probe file length add default case
        placeholder = ""
        if (len(probe_titles) > 0):
            placeholder += "0"
        for i in range(1, len(probe_titles)):
            placeholder += ":0"
        probe_data.append(('-' * len(probe_titles), placeholder))


def calcInfoOffsets(file):
    global info_seperations
    global trace_line_offsets
    global trace_stages
    num_stages = len(trace_stages)
    # Get line at bottom of trace pad
    prev_pos = file.tell()
    if (bottom < len(trace_line_offsets)):
        file.seek(trace_line_offsets[bottom])
    else:
        file.seek(trace_line_offsets[-1])
    # Calculate distances between instruction information titles
    split = file.readline().split(':')
    num_len = 0
    cycle_len = 0
    pc_len = 0
    num_len = len(split[num_stages +
                        2]) if len(split[num_stages + 2]) > 9 else 9
    cycle_len = len(split[0]) if len(split[0]) > 7 else 7
    pc_len = len(split[num_stages]) if len(split[num_stages]) > 4 else 4
    cycle_title_offset = 3 + num_len
    pc_title_offset = 2 + cycle_title_offset + cycle_len
    disasm_title_offset = 2 + pc_title_offset + pc_len
    info_seperations = [
        1, cycle_title_offset, pc_title_offset, disasm_title_offset
    ]
    # Reset file pointer
    file.seek(prev_pos)


def visualiser(trace, probe):
    global top
    global bottom
    global width_left
    global debug_string
    global probe_data
    global trace_data
    global info_seperations
    global selected_probes
    global probes_active
    # Initialise data lists with default values
    placeholder = ""
    if (len(probe_titles) > 0):
        placeholder += "0"
    for i in range(1, len(probe_titles)):
        placeholder += ":0"
    probe_data = [(len(probe_titles) * '.', placeholder)
                  ] * (probe_file_length + 1)
    trace_data = [(0, "", "", 0)] * trace_file_length
    # Initialise curses instance and main screen
    screen = curses.initscr()
    curses.noecho()
    curses.cbreak()
    screen.keypad(True)
    curses.start_color()
    # Set colours mappings
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_RED)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_BLUE)
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_MAGENTA)
    curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)
    # Included so curses instance is exited upon program crash
    try:
        # Get initial screen dimensions
        y, x = screen.getmaxyx()
        # Get number of active probes
        for entry in selected_probes:
            if entry:
                probes_active += 1
        # Set size of probe section, min of 1
        probe_length = probes_active if probes_active > 0 else 1
        # Quit program if terminal size is too small
        if (x >= 49 and y >= (5 + probe_length)):
            win_rows_top = y - probe_length - 2
            win_rows_bot = probe_length + 2
            pad_top_rows = win_rows_top - 2
            pad_bot_rows = win_rows_bot - 2
            # Clear screen
            screen.erase()
            screen.noutrefresh()
            # Set trace window dimension limits
            top = 0
            bottom = pad_top_rows if pad_top_rows < trace_file_length else trace_file_length
            # Read initial traces to fill trace pad
            calcInfoOffsets(trace)
            for i in range(top, bottom):
                readTrace(trace, i)
            for j in range(trace_data[top][0] - 1,
                           trace_data[top][0] + width_left + 1):
                readProbe(probe, j)
            # Set column sizes based on width of current trace lines
            win_cols_left = width_left + 3 if width_left + 3 < (math.trunc(
                x / 4)) else math.trunc(x / 4)
            win_cols_right = x - win_cols_left
            title_cols = math.trunc(win_cols_right / 4)
            asct_insn_cols = win_cols_right - title_cols
            pad_left_cols = width_left + 1
            # Create window classes
            win1 = Window(win_rows_top, win_cols_left, 0, 0, ["[TIMELINE]"])
            win2 = Window(win_rows_bot, win_cols_left, win_rows_top, 0,
                          ["[PROBE]"])
            win3 = Window(win_rows_top, win_cols_right, 0, win_cols_left,
                          ["[INSN_NUM]", "[CYCLE]", "[PC]", "[DISASM]"])
            win4 = Window(win_rows_bot, title_cols, win_rows_top,
                          win_cols_left, ["[PROBES SELECTED]"])
            win5 = Window(win_rows_bot, asct_insn_cols, win_rows_top,
                          win_cols_left + title_cols,
                          ["[ASSOCIATED_INSTRUCTIONS]"])
            # Create pad classes and draw initial trace/probe data
            pad1 = TracePad(pad_top_rows, pad_left_cols, 0, 0, 1, 1,
                            win_rows_top - 2, win_cols_left - 2)
            pad1.redraw(top, bottom, win_cols_left - 2)
            pad2 = ProbePad(pad_bot_rows + 1, pad_left_cols, 0, 0,
                            win_rows_top + 1, 1, y - 2, win_cols_left - 2)
            pad2.redraw(top, win_cols_left - 2)
            pad3 = InfoPad(pad_top_rows, win_cols_right - 2, 0, 0, 1,
                           win_cols_left + 1, win_rows_top - 2, x - 2)
            pad3.redraw(top, bottom, win_cols_right - 2)
            pad4 = TitlePad(pad_bot_rows, title_cols - 2, 0, 0,
                            win_rows_top + 1, win_cols_left + 1, y - 2,
                            win_cols_left + title_cols - 2)
            pad4.redraw(title_cols - 2)
            pad5 = AssociatedPad(pad_bot_rows, asct_insn_cols - 2, 0, 0,
                                 win_rows_top + 1,
                                 win_cols_left + title_cols + 1, y - 2, x - 2)
            pad5.redraw(top, asct_insn_cols - 2)
            # Update screen
            curses.doupdate()
            # Display loop
            running = True
            queued = False
            while (running):
                k = screen.getch()
                if k == curses.KEY_RESIZE:
                    # Terminal resize
                    # Reset screen dimension variables
                    y, x = screen.getmaxyx()
                    probe_length = probes_active if probes_active > 0 else 1
                    win_rows_top = y - probe_length - 2
                    win_rows_bot = probe_length + 2
                    pad_top_rows = win_rows_top - 2
                    pad_bot_rows = win_rows_bot - 2
                    bottom = top + pad_top_rows if top + pad_top_rows < trace_file_length else trace_file_length
                    # Quit program if terminal size is too small
                    if (x < 49 or y < (5 + probe_length)):
                        running = False
                        break
                elif k == curses.KEY_DOWN:
                    # Scroll down
                    if bottom < trace_file_length:
                        bottom += 1
                        top += 1
                elif k == curses.KEY_UP:
                    # Scroll up
                    if top > 0:
                        # Only move bottom instruction pointer if trace pad is full
                        if (((bottom - top) == (pad_top_rows))
                                or ((bottom - top) == trace_file_length)):
                            bottom -= 1
                        top -= 1
                elif k == curses.KEY_LEFT:
                    # Scroll left
                    pad1.x_pos -= 1 if pad1.x_pos > 0 else 0
                    pad2.x_pos -= 1 if pad2.x_pos > 0 else 0
                    pad3.x_pos -= 1 if pad3.x_pos > 0 else 0
                    pad4.x_pos -= 1 if pad4.x_pos > 0 else 0
                    pad5.x_pos -= 1 if pad5.x_pos > 0 else 0
                elif k == curses.KEY_RIGHT:
                    # Scroll right
                    pad1.x_pos += 1 if (pad1.x_pos + win_cols_left -
                                        2) < width_left else 0
                    pad2.x_pos += 1 if (pad2.x_pos + win_cols_left -
                                        2) < width_left else 0
                    pad3.x_pos += 1 if (pad3.x_pos + win_cols_right -
                                        2) < pad3.cols - 1 else 0
                    pad4.x_pos += 1 if (pad4.x_pos + title_cols -
                                        2) < pad4.cols - 1 else 0
                    pad5.x_pos += 1 if (pad5.x_pos + asct_insn_cols -
                                        2) < pad5.cols - 1 else 0
                elif k == curses.KEY_NPAGE:
                    # Jump down block equal to the current trace view length (PG_DOWN)
                    if bottom + pad_top_rows < trace_file_length:
                        bottom += pad_top_rows
                        top += pad_top_rows
                    else:
                        increment = (trace_file_length - bottom)
                        bottom += increment
                        top += increment
                elif k == curses.KEY_PPAGE:
                    # Jump up block equal to the current trace view length (PG_UP)
                    # If jump doesn't go to negative index
                    if (top - pad_top_rows) > 0:
                        # Only move bottom instruction pointer if trace pad is full
                        if (((bottom - top) == (pad_top_rows))
                                or ((bottom - top) == trace_file_length)):
                            bottom -= pad_top_rows
                        top -= pad_top_rows
                        # Ensure instruction bound selection doesn't overflow trace pad length
                        if (bottom == trace_file_length):
                            top = trace_file_length - pad_top_rows
                    else:
                        if (((bottom - top) == (pad_top_rows))
                                or ((bottom - top) == trace_file_length)):
                            bottom -= top
                        top -= top
                elif chr(k) == 'j' or chr(k) == 'J':
                    y, x = screen.getmaxyx()
                    winTemp = Window(3, math.trunc(x / 3),
                                     math.trunc(y / 2) - 1, math.trunc(x / 3),
                                     ["[JUMP_TO]"])
                    typing = True
                    input = ""
                    # Update screen
                    curses.doupdate()
                    # Get user input for line to jump to
                    while (typing):
                        l = screen.getch()
                        if (chr(l) == 'z' or chr(l) == 'Z'):
                            # Exit
                            typing = False
                            input = ""
                            break
                        elif (l == 10):
                            # Submit
                            typing = False
                            break
                        elif (l == curses.KEY_RESIZE):
                            typing = False
                            queued = True
                            # Queue resize for main display loop
                            curses.ungetch(l)
                            break
                        elif (l == curses.KEY_BACKSPACE):
                            winTemp.reset()
                            input = input[:-1]
                        elif (l < 58 and l > 47):
                            # Input allows numbers only
                            input += chr(l)
                        # Add inputted value as string to pad
                        if (len(input) > (winTemp.cols - 2)):
                            winTemp.win.addstr(
                                1, 1, input[(len(input) - winTemp.cols + 2):])
                        else:
                            winTemp.win.addstr(1, 1, input)
                        winTemp.win.noutrefresh()
                        # Update screen
                        curses.doupdate()
                    # Jump view range for trace and probe data
                    if (input != "" and trace_file_length > pad_top_rows):
                        newIndex = int(input) - 1
                        if (newIndex < 0):
                            newIndex = 0
                        if (newIndex + pad_top_rows > trace_file_length):
                            newIndex = trace_file_length - pad_top_rows
                        top = newIndex
                        bottom = top + pad_top_rows
                    del winTemp
                elif chr(k) == 'p' or chr(k) == 'P':
                    y, x = screen.getmaxyx()
                    selecting = True
                    index = 0
                    # Create temporary window for selecting probes
                    winTemp_rows = len(probe_titles) + 2 if math.trunc(
                        y / 2) >= len(probe_titles) + 2 else math.trunc(y / 2)
                    winTemp_cols = math.trunc(x / 2)
                    winTemp = Window(winTemp_rows, winTemp_cols,
                                     math.trunc(y / 4), math.trunc(x / 4),
                                     ["[PROBE_SELECTION]"])
                    # Create temporary pad for selecting probes
                    padTemp_rows = len(probe_titles)
                    padTemp_cols = winTemp_cols - 2
                    start_y_loc = math.trunc(y / 4) + 1
                    start_x_loc = math.trunc(x / 4) + 1
                    end_y_loc = start_y_loc - 3 + winTemp_rows
                    end_x_loc = start_x_loc - 3 + winTemp_cols
                    padTemp = SelectionPad(padTemp_rows, padTemp_cols, 0, 0,
                                           start_y_loc, start_x_loc, end_y_loc,
                                           end_x_loc)
                    padTemp.redraw(winTemp_cols - 2, index)
                    # Update screen
                    curses.doupdate()
                    # Get user input for line to jump to
                    while (selecting):
                        l = screen.getch()
                        if (chr(l) == 'z' or chr(l) == 'Z'):
                            # Exit
                            selecting = False
                            queued = True
                            # Queue resize for main display loop
                            curses.ungetch(curses.KEY_RESIZE)
                            break
                        elif (l == curses.KEY_RESIZE):
                            selecting = False
                            queued = True
                            # Queue resize for main display loop
                            curses.ungetch(l)
                            break
                        elif (l == curses.KEY_DOWN):
                            # Move selected probe downwards
                            index += 1 if index < len(probe_titles) - 1 else 0
                            if (index >= winTemp.rows - 2):
                                padTemp.y_pos += 1 if padTemp.y_pos <= (
                                    padTemp.rows - winTemp.rows + 1) else 0
                        elif (l == curses.KEY_UP):
                            # Move selected probe upwards
                            index -= 1 if index > 0 else 0
                            if (index < winTemp.rows - 2):
                                padTemp.y_pos -= 1 if padTemp.y_pos > 0 else 0
                        elif (l == curses.KEY_LEFT):
                            # Scroll probe list left
                            padTemp.x_pos -= 1 if padTemp.x_pos > 0 else 0
                        elif (l == curses.KEY_RIGHT):
                            # Scroll probe list right
                            padTemp.x_pos += 1 if (padTemp.x_pos +
                                                   winTemp.cols -
                                                   2) < padTemp.cols - 1 else 0
                        elif (l == 10):
                            # Toggle probe
                            if selected_probes[index] == 1:
                                selected_probes[index] = 0
                                probes_active -= 1 if probes_active > 0 else 0
                            else:
                                selected_probes[index] = 1
                                probes_active += 1 if probes_active < len(
                                    probe_titles) else 0
                        elif (chr(l) == 'a' or chr(l) == 'A'):
                            # Select all probes
                            probes_active = len(probe_titles)
                            selected_probes = len(probe_titles) * [1]
                        elif (chr(l) == 'n' or chr(l) == 'N'):
                            # Deselect all probes
                            probes_active = 0
                            selected_probes = len(probe_titles) * [0]
                        winTemp.reset()
                        padTemp.reset()
                        padTemp.redraw(winTemp_cols - 2, index)
                        # Update screen
                        curses.doupdate()
                    del winTemp
                    del padTemp
                elif chr(k) == 'q' or chr(k) == 'Q':
                    # Stop display loop
                    running = False
                # Align info window titles and info pad lines
                calcInfoOffsets(trace)
                # Read in new trace and probe lines
                width_left = 0
                for i in range(top, bottom):
                    readTrace(trace, i)
                for j in range(trace_data[top][0] - 1,
                               trace_data[top][0] + width_left + 1):
                    readProbe(probe, j)
                # If key input hasn't been queued
                if not queued:
                    # Set column sizes based on width of current trace lines
                    win_cols_left = width_left + 3 if width_left + 3 < (
                        math.trunc(x / 4)) else math.trunc(x / 4)
                    win_cols_right = x - win_cols_left
                    title_cols = math.trunc(win_cols_right / 4)
                    asct_insn_cols = win_cols_right - title_cols
                    pad_left_cols = width_left + 1
                    # Clear screen
                    screen.erase()
                    screen.noutrefresh()
                    # Redraw windows
                    win1.reset_resize(win_rows_top, win_cols_left, 0, 0)
                    win2.reset_resize(win_rows_bot, win_cols_left,
                                      win_rows_top, 0)
                    win3.reset_resize(win_rows_top, win_cols_right, 0,
                                      win_cols_left)
                    win4.reset_resize(win_rows_bot, title_cols, win_rows_top,
                                      win_cols_left)
                    win5.reset_resize(win_rows_bot, asct_insn_cols,
                                      win_rows_top, win_cols_left + title_cols)
                    # Redraw pads
                    pad1.reset_resize(pad_top_rows, pad_left_cols, 1, 1,
                                      win_rows_top - 2, win_cols_left - 2)
                    pad1.redraw(top, bottom, win_cols_left - 2)
                    pad2.reset_resize(pad_bot_rows + 1, pad_left_cols,
                                      win_rows_top + 1, 1, y - 2,
                                      win_cols_left - 2)
                    pad2.redraw(top, win_cols_left - 2)
                    pad3.reset_resize(pad_top_rows, win_cols_right - 2, 1,
                                      win_cols_left + 1, win_rows_top - 2,
                                      x - 2)
                    pad3.redraw(top, bottom, win_cols_right - 2)
                    pad4.reset_resize(pad_bot_rows, title_cols - 2,
                                      win_rows_top + 1, win_cols_left + 1,
                                      y - 2, win_cols_left + title_cols - 2)
                    pad4.redraw(title_cols - 2)
                    pad5.reset_resize(pad_bot_rows, asct_insn_cols - 2,
                                      win_rows_top + 1,
                                      win_cols_left + title_cols + 1, y - 2,
                                      x - 2)
                    pad5.redraw(top, asct_insn_cols - 2)
                    # Update screen
                    curses.doupdate()
                else:
                    queued = False
                    # Clear screen
                    screen.erase()
                    screen.noutrefresh()
                    # Update screen
                    curses.doupdate()
            # End curses instance
            screen.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()
            # Delete curses objects
            del win1
            del win2
            del win3
            del win4
            del win5
            del pad1
            del pad2
            del pad3
            del pad4
            del pad5
        # Close files
        trace.close()
        probe.close()
        # End curses instance
        screen.keypad(False)
        curses.nocbreak()
        curses.echo()
        curses.endwin()
    finally:
        # Close files
        trace.close()
        probe.close()
        # End curses instance
        screen.keypad(False)
        curses.nocbreak()
        curses.echo()
        curses.endwin()


def main():
    global trace_data
    global trace_line_offsets
    global probe_data
    global probe_line_offsets
    global trace_stages
    parser = argparse.ArgumentParser()
    parser.add_argument('trace', help='Input directory for trace file')
    parser.add_argument('probe', help='Input directory for probe file')
    parser.add_argument(
        'stages',
        help=
        'A string of single character pipeline stages used in generation of trace file'
    )
    parser.add_argument('--force',
                        action='store_true',
                        default=False,
                        help='Force the rewrite of .cache files')
    args = parser.parse_args()
    # Create or read byte offsets for trace and probe files
    probe_line_offsets = cacheLineOffsets(args.probe, args.force, "probe")
    trace_line_offsets = cacheLineOffsets(args.trace, args.force, "trace")
    # Split stages argument into trace_stages
    trace_stages = [s for s in args.stages]
    with open(args.trace, 'r') as trace:
        with open(args.probe, 'r') as probe:
            visualiser(trace, probe)
            # Delete trace and probe data related objects
            del trace_data
            del trace_line_offsets
            del probe_data
            del probe_line_offsets


if __name__ == '__main__':
    main()
