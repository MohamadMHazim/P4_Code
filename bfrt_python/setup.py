from ipaddress import ip_address

p4 = bfrt.basic.pipe

forwarding = p4.Ingress.forwarding

forwarding.clear()

forwarding.add_with_send_using_port(ingress_port= 0,   port=1)
forwarding.add_with_send_using_port(ingress_port= 1,   port=0)



bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table forwarding:")
forwarding.dump(table=True)
                       
