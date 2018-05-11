#!/usr/bin/env python



import angr
import os


test_func_addr= 0x000000000040069c

def main():
    project= angr.Project("sample_elf/test_elf")
    #symbolic execution from the func addr
    entry_state =  project.factory.blank_state(addr=test_func_addr)
    pg = project.factory.simgr(entry_state,save_unconstrained=True)
    os.system('rm /tmp/find_read.flag')
    findflag=0
    #symbolic execution until the unconstrained successor
    while len(pg.unconstrained)==0:
        if(os.path.isfile('/tmp/find_read.flag')):
            findflag=1
            break
        pg.step()
    if(len(pg.unconstrained)!=0):
        unconstrained_path = pg.unconstrained[0]
    print 'ok'

    '''
    crashing_input = unconstrained_path.state.posix.dumps(0)
    #cat crash_input.bin | ./CADET_00001.adapted will segfault
    unconstrained_path.state.posix.dump(0,"crash_input.bin")
    print "buffer overflow found!"
    print repr(crashing_input)


    #let's now find the easter egg (it takes about 2 minutes)

    #now we want angr to avoid "unfeasible" paths
    #by default, "lazy solving" is enabled, this means that angr will not
    #automatically discard unfeasible paths

    #to disable "lazy solving" we generate a blank path and we change its options,
    #then we specify this path as the initial path of the path group
    print "finding the easter egg..."
    path = project.factory.path()
    path.state.options.discard("LAZY_SOLVES")
    pg = project.factory.path_group(path)

    #at this point we just ask angr to reach the basic block where the easter egg
    #text is printed
    pg.explore(find=0x804833E)
    found = pg.found[0]
    solution1 = found.state.posix.dumps(0)
    print "easter egg found!"
    print repr(solution1)
    found.state.posix.dump(0,"easteregg_input1.bin")
    #you can even check if the easter egg has been found by checking stdout
    stdout1 = found.state.posix.dumps(1)
    print repr(stdout1)

    #an alternative way to avoid unfeasible paths (paths that contain an unsatisfiable set
    #of constraints) is to "manually" step the path group execution and call prune()
    print "finding the easter egg (again)..."
    pg = project.factory.path_group()
    while True:
        pg.step()
        pg.prune() #we "manually" ask angr to remove unfeasible paths
        found_list = [active for active in pg.active if active.addr == 0x804833E]
        if len(found_list) > 0:
            break
    found = found_list[0]
    solution2 = found.state.posix.dumps(0)
    print "easter egg found!"
    print repr(solution2)
    found.state.posix.dump(0,"easteregg_input2.bin")
    #you can even check if the easter egg has been found by checking stdout
    stdout2 = found.state.posix.dumps(1)
    print repr(stdout2)

    return (crashing_input, solution1, stdout1, solution2, stdout2)
    '''





if __name__ == '__main__':
    main()


