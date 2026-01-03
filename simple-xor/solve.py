import angr
import claripy

def main():
    proj = angr.Project('simple-xor', auto_load_libs=False)

    chars = [claripy.BVS('char_%d' % i, 8) for i in range(32)]
    input_arg = claripy.Concat(*chars)

    state = proj.factory.entry_state(args=["./simple-xor", input_arg])
    state.options.discard(angr.options.LAZY_SOLVES)

    for k in chars:
        state.solver.add(k < 0x7f)
        state.solver.add(k > 0x20)

    sm = proj.factory.simulation_manager(state)
    sm.explore( find=lambda s: b"Pass valid!" in s.posix.dumps(1), avoid=lambda s: b"Nope." in s.posix.dumps(1) )
    
    if sm.found:
        input_value = sm.found[0].solver.eval(input_arg, cast_to=bytes)
        print(f"{input_value}")
    else:
        print("Failed!")

if __name__ == "__main__":
    main()
