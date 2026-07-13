from slither import Slither
from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall
from core.destination_origin import resolve_destination_origin, DestinationOrigin

TARGET_FUNCTIONS = {"supply", "liquidate", "setFee", "repay"}

sl = Slither("fixture/morpho_blue/src/Morpho.sol")

for contract in sl.contracts:
    for function in contract.functions:
        if function.name not in TARGET_FUNCTIONS:
            continue
        if not function.is_implemented:
            continue

        print(f"\n=== {contract.name}.{function.name}() ===")
        found_call = False

        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, (HighLevelCall, LibraryCall, LowLevelCall)):
                    found_call = True
                    origin = resolve_destination_origin(ir, function)
                    call_kind = type(ir).__name__
                    dest = getattr(ir, "destination", None)
                    func_called = getattr(ir, "function_name", None) or getattr(ir, "function", None)
                    print(f"  [{call_kind}] -> {func_called}")
                    print(f"    destination var: {dest}")
                    print(f"    origin: {origin}")

        if not found_call:
            print("  (no HighLevelCall/LibraryCall/LowLevelCall found)")
