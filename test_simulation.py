from client import Client
from simulate_ddos import simulate_ddos

def run_tests():
    # Clear log file
    open("simulation_log.txt", "w").close()

    # Test 1: Normal Traffic
    print("\n=== Test 1: Normal Traffic ===")
    normal_clients = [Client(f"Normal Client {i}", request_rate=2) for i in range(3)]
    simulate_ddos(duration=30, normal_clients=normal_clients, attackers=[])

    # Test 2: DDoS Attack
    print("\n=== Test 2: DDoS Attack ===")
    attackers = [Client(f"Attacker {i}", request_rate=70, is_attacker=True) for i in range(10)]
    normal_clients = [Client(f"Normal Client {i}", request_rate=2) for i in range(2)]
    simulate_ddos(duration=120 , normal_clients=normal_clients, attackers=attackers)

    # Test 3: Mixed Traffic
    print("\n=== Test 3: Mixed Traffic ===")
    attackers = [Client(f"Attacker {i}", request_rate=70, is_attacker=True) for i in range(3)]
    normal_clients = [Client(f"Normal Client {i}", request_rate=3) for i in range(5)]
    simulate_ddos(duration=120, normal_clients=normal_clients, attackers=attackers)

    # Test 4: Edge Case - Failure to Detect
    print("\n=== Test 4: Edge Case - Failure to Detect ===")
    attackers = [Client(f"Attacker {i}", request_rate=100, is_attacker=True) for i in range(10)]
    simulate_ddos(duration=120, normal_clients=[], attackers=attackers, failed_detection=True)

if __name__ == "__main__":
    run_tests()
