import angr
import claripy

def main():
    proj = angr.Project(
            'good-kitty', 
            auto_load_libs=False,
            main_opts={
                "base_addr": 0x555555554000
            }
        )

    chars = [claripy.BVS('char_%d' % i, 8) for i in range(64)]
    input_arg = claripy.Concat(*chars)

    state = proj.factory.blank_state(addr=0x555555555539)

    
    for k in chars:
        state.solver.add(k < 0x7f)
        state.solver.add(k > 0x20)

    STACK_BASE = 0x7fffffffdc80
    STACK_SIZE = 0x1000

    state.memory.map_region(
        STACK_BASE - STACK_SIZE,
        STACK_SIZE,
        7
    )

    state.regs.rsp = STACK_BASE
    state.regs.rax = claripy.BVS("rax", 64)
    
    state.memory.store(
        state.regs.rsp + 0xb,
        claripy.BVV(1, 8)
    )
    state.memory.store(
        state.regs.rsp + 0xc,
        claripy.BVV(0, 32)
    )
    state.memory.store(
        state.regs.rsp + 0x60,
        input_arg
    )
    state.memory.store(
        state.regs.rsp + 0x10,
        b"00sGo4M0passwordenter the right password\x00"
    )

    sm = proj.factory.simulation_manager(state)
    sm.explore( find=lambda s: b"good kitty!" in s.posix.dumps(1), avoid=lambda s: b"bad kitty!" in s.posix.dumps(1) )
    
    if sm.found:
        input_value = sm.found[0].solver.eval(input_arg, cast_to=bytes)
        print(f"{input_value}")
    else:
        print("Bad kitty!")

if __name__ == "__main__":
    main()
