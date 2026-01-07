import angr
import claripy

def main():
    proj = angr.Project('bingus', auto_load_libs=False)

    input_1 = claripy.BVS("input", 8*2)
    
    state = proj.factory.entry_state(args=["./bingus", input_1])
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    sm = proj.factory.simulation_manager(state)
    sm.explore( find=lambda s: b"Bingus survived" in s.posix.dumps(1))
    
    if sm.found:
        input_1 = sm.found[0].solver.eval(input_1, cast_to=bytes)
        print(f"{input_1}")
    else:
        print("Failed!")

if __name__ == "__main__":
    main()
