# feb/15/2021 14:59:29 by RouterOS 6.47.3
# software id = 0QM9-6SVP
#
#
#
/system script
add dont-require-permissions=no name=startup_set_global_vars owner=admin \
    policy=read,write,policy,test source=":global GlobalVar \"Value\""
