class RopChain(object):
    """
    This class holds rop chains returned by the rop chain building methods such as rop.set_regs()
    """
    def __init__(self, project, rop, state=None):
        self._p = project
        self._rop = rop

        self._gadgets = []
        self._values = []
        self.payload_len = 0

        # blank state used for solving
        self._blank_state = self._p.factory.blank_state() if state is None else state
        self._pie = self._p.loader.main_bin.rebase_addr != 0
        self._rebase_val = self._blank_state.se.BVS("base", self._p.arch.bits)

    def __add__(self, other):
        # need to add the values from the other's stack and the constraints to the result state
        result = self.copy()
        o_state = other._blank_state
        o_stack = o_state.memory.load(o_state.regs.sp, other.payload_len)
        result._blank_state.memory.store(result._blank_state.regs.sp + self.payload_len, o_stack)
        result._blank_state.se.constraints.extend(o_state.se.constraints)
        # add the other values and gadgets
        result._values.extend(other._values)
        result._gadgets.extend(other._gadgets)
        result.payload_len = self.payload_len + other.payload_len
        return result

    def add_value(self, value, needs_rebase=False):
        # override rebase if its not pie
        if not self._pie:
            needs_rebase = False
        if needs_rebase:
            value -= self._p.loader.main_bin.rebase_addr
        self._values.append((value, needs_rebase))
        self.payload_len += self._p.arch.bits/8

    def add_gadget(self, gadget):
        self._gadgets.append(gadget)

    def add_constraint(self, cons):
        """
        helpful if the chain contains variables
        """
        self._blank_state.add_constraints(cons)

    def _concretize_chain_values(self, constraints=None):
        """
        we all the flexibilty of chains to have symbolic values, this helper function
        makes the chain into a list of concrete ints before printing
        :param constraints: constraints to use when concretizing values
        :return: a list of tuples of type (int, needs_rebase)
        """

        solver_state = self._blank_state.copy()
        if constraints is not None:
            solver_state.add_constraints(constraints)

        concrete_vals = []
        for val, needs_rebase in self._values:
            if isinstance(val, (int, long)):
                concrete_vals.append((val, needs_rebase))
            else:
                concrete_vals.append((solver_state.se.any_int(val), needs_rebase))

        return concrete_vals

    def payload_str(self, constraints=None, base_addr=None):
        if base_addr is None:
            base_addr = self._p.loader.main_bin.rebase_addr
        test_state = self._blank_state.copy()
        concrete_vals = self._concretize_chain_values(constraints)
        for value, needs_rebase in reversed(concrete_vals):
            if needs_rebase:
                test_state.stack_push(value - self._p.loader.main_bin.rebase_addr + base_addr)
            else:
                test_state.stack_push(value)
        sp = test_state.regs.sp
        rop_str = test_state.se.any_str(test_state.memory.load(sp, self.payload_len))
        return rop_str

    def print_payload_code(self, constraints=None):
        if self._p.arch.bits == 32:
            pack = "p32(%#x)"
            pack_rebase = "p32(%#x + base_addr)"
        else:
            pack = "p64(%#x)"
            pack_rebase = "p64(%#x + base_addr)"

        if self._pie:
            payload = "base_addr = 0x0\n"
        else:
            payload = ""
        payload += 'chain = ""\n'
        concrete_vals = self._concretize_chain_values(constraints)
        for value, needs_rebase in concrete_vals:
            if needs_rebase:
                payload += "chain += " + pack_rebase % value
            else:
                payload += "chain += " + pack % value
            payload += "\n"
        print payload

    def copy(self):
        cp = RopChain(self._p, self._rop)
        cp._values = list(self._values)
        cp._gadgets = list(self._gadgets)
        cp.payload_len = self.payload_len
        cp._blank_state = self._blank_state.copy()
        cp._pie = self._pie
        cp._rebase_val = self._rebase_val

        return cp