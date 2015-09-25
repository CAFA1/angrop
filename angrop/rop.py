import angr
import simuvex

import chain_builder
import gadget_analyzer

import pickle
import inspect
import logging
import progressbar

from multiprocessing import Pool

l = logging.getLogger('angrop.rop')


def _str_find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1:
            return
        yield start
        start += 1


_global_gadget_analyzer = None


# global initializer for multiprocessing
def _set_global_gadget_analyzer(rop_gadget_analyzer):
    global _global_gadget_analyzer
    _global_gadget_analyzer = rop_gadget_analyzer


def run_worker(addr):
    return _global_gadget_analyzer.analyze_gadget(addr)


# todo what if we have mov eax, [rsp+0x20]; ret (cache would need to know where it is or at least a min/max)
# todo what if we have pop eax; mov ebx, eax; need to encode that we cannot set them to different values
class ROP(angr.Analysis):
    """
    This class is a semantic aware rop gadget finder
    It is a work in progress, so don't be surprised if something doesn't quite work
    """

    def __init__(self, only_check_near_rets=True, max_block_size=20, max_sym_mem_accesses=4, fast_mode=None):
        """
        Initializes the rop gadget finder
        :param only_check_near_rets: If true we skip blocks that are not near rets
        :param max_block_size: limits the size of blocks considered, longer blocks are less likely to be good rop
                               gadgets so we limit the size we consider
        :param fast_mode: if set to True sets options to run fast, if set to False sets options to find more gadgets
                          if set to None makes a decision based on the size of the binary
        :return:
        """

        # params
        self._max_block_size = max_block_size
        self._only_check_near_rets = only_check_near_rets
        self._max_sym_mem_accesses = max_sym_mem_accesses

        a = self.project.arch
        self._sp_reg = a.register_names[a.sp_offset]
        self._ip_reg = a.register_names[a.ip_offset]
        self._base_pointer = a.register_names[a.bp_offset]

        self._reg_list = a.default_symbolic_registers
        # prune the register list of the instruction pointer and the stack pointer
        self._reg_list = filter(lambda r: r != self._sp_reg, self._reg_list)
        self._reg_list = filter(lambda r: r != self._ip_reg, self._reg_list)

        self._syscall_instructions = {"\x0f\x05"}

        if self.project.arch.linux_name == "x86_64":
            self._syscall_instructions = {"\x0f\x05"}
            self._cc = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            self._execve_syscall = 59
        elif self.project.arch.linux_name == "i386":
            self._syscall_instructions = {"\xcd\x80"}
            self._cc = "stack"
            self._execve_syscall = 11

        # get ret locations
        self._ret_locations = self._get_ret_locations()

        # list of gadgets
        self.gadgets = []
        self._duplicates = []

        num_to_check = len(list(self._addresses_to_check()))
        # fast mode
        if fast_mode is None:
            if num_to_check > 20000:
                fast_mode = True
                l.warning("Enabling fast mode for large binary")
            else:
                fast_mode = False
        self._fast_mode = fast_mode

        if self._fast_mode:
            self._max_block_size = 12
            self._max_sym_mem_accesses = 1
            num_to_check = len(list(self._addresses_to_check()))

        l.info("There are %d addresses withing %d bytes of a ret",
               num_to_check, self._max_block_size)

        # gadget analyzer
        self._gadget_analyzer = gadget_analyzer.GadgetAnalyzer(self.project, self._reg_list, self._max_block_size,
                                                               self._fast_mode, self._max_sym_mem_accesses)
        # chain builder
        self._chain_builder = None

        # silence annoying loggers
        simuvex.vex.ccall.l.setLevel("CRITICAL")
        simuvex.vex.expressions.ccall.l.setLevel("CRITICAL")

    def find_gadgets(self, processes=4):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret.
        Saves gadgets in self.gadgets
        :param processes: number of processes to use
        """
        self.gadgets = []

        pool = Pool(processes=processes, initializer=_set_global_gadget_analyzer, initargs=(self._gadget_analyzer,))

        it = pool.imap_unordered(run_worker, self._addresses_to_check_with_caching(), chunksize=5)
        for gadget in it:
            if gadget is not None:
                self.gadgets.append(gadget)

        pool.close()

        # fix up gadgets from cache
        for g in self.gadgets:
            if g.addr in self._cache:
                dups = {g.addr}
                for addr in self._cache[g.addr]:
                    dups.add(addr)
                    g_copy = g.copy()
                    g_copy.addr = addr
                    self.gadgets.append(g_copy)
                self._duplicates.append(dups)
        self.gadgets = sorted(self.gadgets, key=lambda x: x.addr)
        self._reload_chain_funcs()

    def find_gadgets_single_threaded(self):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret.
        Saves gadgets in self.gadgets
        """
        self.gadgets = []

        _set_global_gadget_analyzer(self._gadget_analyzer)
        for _, addr in enumerate(self._addresses_to_check_with_caching()):
            gadget = _global_gadget_analyzer.analyze_gadget(addr)
            if gadget is not None:
                self.gadgets.append(gadget)

        # fix up gadgets from cache
        for g in self.gadgets:
            if g.addr in self._cache:
                dups = {g.addr}
                for addr in self._cache[g.addr]:
                    dups.add(addr)
                    g_copy = g.copy()
                    g_copy.addr = addr
                    self.gadgets.append(g_copy)
                self._duplicates.append(dups)
        self.gadgets = sorted(self.gadgets, key=lambda x: x.addr)
        self._reload_chain_funcs()

    def save_gadgets(self, path):
        with open(path, "wb") as f:
            pickle.dump((self.gadgets, self._duplicates), f)

    def load_gadgets(self, path):
        self.gadgets, self._duplicates = pickle.load(open(path, "rb"))
        self._reload_chain_funcs()

    def _reload_chain_funcs(self):
        for f_name, f in inspect.getmembers(self.chain_builder, predicate=inspect.ismethod):
            if f_name.startswith("_"):
                continue
            setattr(self, f_name, f)

    @property
    def chain_builder(self):
        if self._chain_builder is not None:
            return self._chain_builder
        elif len(self.gadgets) > 0:
            self._chain_builder = chain_builder.ChainBuilder(self.project, self.gadgets, self._duplicates,
                                                             self._reg_list)
            return self._chain_builder
        else:
            raise Exception("No gadgets, call find_gadgets() or load_gadgets() first")

    def _block_has_ip_relative(self, addr, bl):
        string = bl.bytes
        test_addr = 0x41414140 + addr % 0x10
        bl2 = self.project.factory.block(test_addr, insn_bytes=string)
        # TODO: FIXME
        try:
            diff_constants = angr.bindiff.differing_constants(bl, bl2)
        except angr.analyses.bindiff.UnmatchedStatementsException:
            return True
        # check if it changes if we move it
        bl_end = addr + bl.size
        bl2_end = test_addr + bl2.size
        filtered_diffs = []
        for d in diff_constants:
            if d.value_a < addr or d.value_a >= bl_end or \
                    d.value_b < test_addr or d.value_b >= bl2_end:
                filtered_diffs.append(d)
        return len(filtered_diffs) > 0

    def _addresses_to_check_with_caching(self, show_progress=True):
        num_addrs = len(list(self._addresses_to_check()))
        widgets = ['ROP: ', progressbar.Percentage(), ' ',
                   progressbar.Bar(marker=progressbar.RotatingMarker()),
                   ' ', progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]
        progress = progressbar.ProgressBar(widgets=widgets, maxval=num_addrs)
        if show_progress:
            progress.start()
        self._cache = dict()
        seen = dict()
        for i, a in enumerate(self._addresses_to_check()):
            if show_progress:
                progress.update(i)
            try:
                bl = self.project.factory.block(a)
                if bl.size > self._max_block_size:
                    continue
                block_data = bl.bytes
            except angr.AngrTranslationError:
                continue
            if block_data in seen:
                self._cache[seen[block_data]].add(a)
                continue
            else:
                if len(bl.vex.constant_jump_targets) == 0 and not self._block_has_ip_relative(a, bl):
                    seen[block_data] = a
                    self._cache[a] = set()
                yield a
        if show_progress:
            progress.finish()

    def _addresses_to_check(self):
        """
        :return: all the addresses to check
        """
        if self._only_check_near_rets:
            # align block size
            alignment = self.project.arch.instruction_alignment
            block_size = (self._max_block_size & ((1 << self.project.arch.bits) - alignment)) + alignment
            slices = [(addr-block_size, addr) for addr in self._ret_locations]
            current_addr = 0
            for st, ed in slices:
                current_addr = max(current_addr, st)
                end_addr = st + block_size + alignment
                for i in range(current_addr, end_addr, alignment):
                    if self.project.loader.main_bin.find_segment_containing(i).is_executable:
                        yield i
                current_addr = max(current_addr, end_addr)
        else:
            raise NotImplementedError("this mode is not implemented in the arch agnostic branch")

    def _get_ret_locations(self):
        """
        :return: all the locations in the binary with a ret instruction
        """
        addrs = [ ]
        seen = set()
        for segment in self.project.loader.main_bin.segments:
            if segment.is_executable:
                min_addr = segment.min_addr + self.project.loader.main_bin.rebase_addr
                num_bytes = segment.max_addr-segment.min_addr

                alignment = self.project.arch.instruction_alignment
                # iterate backwards through the code looking for rets
                # align num_bytes if need
                num_bytes = num_bytes & ((1 << self.project.arch.bits) - alignment)
                for offset in xrange(num_bytes, 0, -alignment):
                    block = self.project.factory.block(min_addr+offset)
                    if block.vex.jumpkind.startswith("Ijk_Ret"):
                        if not block.addr + block.size in seen:
                            addrs.append(min_addr+offset)
                            seen.add(min_addr+offset+block.size)

        return sorted(addrs)

angr.analysis.register_analysis(ROP, 'ROP')
