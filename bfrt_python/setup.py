p4 = bfrt.basic.pipe
forwarding = p4.Ingress.forwarding

forwarding.clear()

forwarding.add_with_send_using_port(ingress_port=0, port=1)
forwarding.add_with_send_using_port(ingress_port=1, port=0)

bfrt.complete_operations()

print("Forwarding table programmed:")
forwarding.dump(table=True)
