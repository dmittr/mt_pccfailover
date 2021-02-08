
/system script
add dont-require-permissions=no name=mt_pccfailover owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="#\
    ################# Variables ##################\
    \n:global LOG 0\
    \n:global OUT 1\
    \n:local PINGCOUNT 10\
    \n:local TARGETS [ :toarray \"8.8.8.8,8.8.4.4,77.88.8.8,77.88.8.1\" ]\
    \n:local TIMEOUT \"0.2\"\
    \n:local LOSTTOLERANCE 1\
    \n:local COMMENT \"--ispswitch script--\"\
    \n:local LANIFLIST \"LAN\"\
    \n:local WANIFLIST \"WAN\"\
    \n\
    \n###############################################\
    \n:global LASTCHANGE\
    \n:local WANIF\
    \n:local IFNAME\
    \n:local IFADDR\
    \n:local IFADDRMASK\
    \n:local IFROUTE\
    \n:local SKIP\
    \n:local MSG\
    \n:local WANS\
    \n:local WANARRAY\
    \n:local WANCOUNT 0\
    \n:local WANBACKUP\
    \n:local WEIGHT\
    \n:local WEIGHTSUMM 0\
    \n:local RCVD\
    \n:local SENT\
    \n:local LOST\
    \n:local LOSTMINIMUM 9999\
    \n:local COUNTER\
    \n\
    \n################## Functions ##################\
    \n:local OUTLOG do={\
    \n\t:global LOG\
    \n\t:global OUT\
    \n\tif ( \$OUT > 0 ) do {\
    \n\t\t:put \"\$1\"\
    \n\t}\
    \n\tif ( \$LOG > 0 ) do {\
    \n\t\t:log info \"\$1\"\
    \n\t}\
    \n}\
    \n:local GETPARAM do={\
    \n\t:local part [ :pick \"\$1\" ([:find \"\$1\" \"\$2\"]+([:len \"\$2\"])+\
    1) [ :len \$1 ] ]\
    \n\tif ( [:find \$part \" \"] ) do={\
    \n\t\t:set part [ :pick \$part 0 ([:find \$part \" \"]) ]\
    \n\t}\
    \n\t:return \$part\
    \n}\
    \n###############################################\
    \n\
    \n:set MSG \"Start!\\n\\r LOG=\$LOG\\n\\r OUT=\$OUT\"\
    \nif ( \$OUT > 0 ) do {\
    \n\t:put \"\$MSG\"\
    \n}\
    \n\
    \n### Check WANIFLIST exist #####################\
    \nif ( [ /interface list member find list=\$WANIFLIST ] = \"\" ) do={\
    \n\t:error \"Create interface list \$WANIFLIST and fill it\"\
    \n}\
    \n\
    \n### Create default address lists ##############\
    \nif ( [ /ip firewall address-list find list=private_nets ] = \"\" ) do={\
    \n\t/ip firewall address-list add address=10.0.0.0/8 list=private_nets\
    \n\t/ip firewall address-list add address=172.16.0.0/12 list=private_nets\
    \n\t/ip firewall address-list add address=192.168.0.0/16 list=private_nets\
    \n}\
    \n\
    \n:set WANIF [ /interface list member find list=\$WANIFLIST ]\
    \n:foreach IF in=\$WANIF do={\
    \n\t:set SKIP 0\
    \n\t:set IFNAME [ /interface list member get \$IF interface ]\
    \n\t:set IFADDR 0\
    \n\t:set IFROUTE 0\
    \n\tif ( [ /ip address get [ /ip address find interface=\$IFNAME ] address\
    \_] = \"\" ) do={\
    \n\t\t:set SKIP 1\
    \n\t} else={\
    \n\t\t:set IFADDRMASK [ /ip address get [ /ip address find interface=\$IFN\
    AME ] address ]\
    \n\t\t:set IFADDR [ :pick \$IFADDRMASK 0 [:find \$IFADDRMASK \"/\" ] ]\
    \n\t}\
    \n\tif ( [ /ip route find comment~\"ISP-\$IFNAME\" ] = \"\" ) do={\
    \n\t\t:set SKIP 1\
    \n\t} else={\
    \n\t\t:set IFROUTE [ /ip route get [ /ip route find comment~\"ISP-\$IFNAME\
    \" ] gateway ]\
    \n\t}\
    \n\tif ( \$IFADDR = 0 ) do={\
    \n### Skip WAN interface wihout address #########\
    \n\t\t:set SKIP 1\
    \n\t} \
    \n\tif ( \$IFROUTE = 0 ) do={\
    \n### Skip WAN interface wihout route comment ###\
    \n\t\t:set SKIP 1\
    \n\t} \
    \n\t:set MSG \"IFNAME=\$IFNAME IFADDR=\$IFADDR IFROUTE=\$IFROUTE SKIP=\$SK\
    IP\"\
    \n\t\$OUTLOG \$MSG\
    \n\t\
    \n\tif ( \$SKIP = 0 ) do={\
    \n### Get WAN interface weight ##################\
    \n\t\t:set WEIGHT [ \$GETPARAM [ /ip route get [ /ip route find comment~\"\
    ISP-\$IFNAME\" ] comment ] \"weight\" ]\
    \n\t\tif ( [ :len \$WEIGHT ] != 1 ) do={\
    \n\t\t\t:set WEIGHT 1\
    \n\t\t}\
    \n\t\tif ( [ /ip route find gateway=\$IFROUTE routing-mark=\"WAN-RM-\$IFNA\
    ME\" comment=\$COMMENT ] = \"\" ) do={\
    \n### Create routing table for each WAN #########\
    \n\t\t\t:set MSG \"Creating route with mark for \$IFNAME\"\
    \n\t\t\t\$OUTLOG \$MSG\
    \n\t\t\t/ip route add gateway=\$IFROUTE routing-mark=\"WAN-RM-\$IFNAME\" c\
    omment=\$COMMENT\
    \n\t\t}\
    \n\t\tif ( [ /ip route rule find src-address=\"\$IFADDR/32\" table=\"WAN-R\
    M-\$IFNAME\" comment=\$COMMENT ] = \"\" ) do={\
    \n### Create routing rule for each WAN ##########\
    \n\t\t\t:set MSG \"Creating route rule for \$IFNAME\"\
    \n\t\t\t\$OUTLOG \$MSG\
    \n\t\t\t/ip route rule add src-address=\"\$IFADDR/32\" table=\"WAN-RM-\$IF\
    NAME\" comment=\$COMMENT\
    \n\t\t}\
    \n\t\t:set RCVD 0\
    \n\t\t:set SENT 0\
    \n### Make icmp tests ###########################\
    \n\t\t:foreach TARGET in \$TARGETS do={\
    \n\t\t\t:for n from=1 to=\$PINGCOUNT step=1 do={\
    \n\t\t\t\t:set RCVD ( [ /ping \$TARGET src-address=\$IFADDR interval=\"\$T\
    IMEOUT\" count=1 ] + \$RCVD )\
    \n\t\t\t\t:set SENT ( \$SENT + 1 )\
    \n\t\t\t}\
    \n\t\t}\
    \n\t\t:set LOST (\$SENT - \$RCVD)\
    \n\t\t:set WANS ( \$WANS , \"\$IFNAME A:\$IFADDRMASK W:\$WEIGHT L:\$LOST\"\
    \_)\
    \n\t\t:set WEIGHTSUMM (\$WEIGHTSUMM + \$WEIGHT)\
    \n\t\tif ( \$LOST <= \$LOSTMINIMUM ) do={\
    \n\t\t\t:set LOSTMINIMUM \$LOST\
    \n\t\t}\
    \n\t\t:set MSG \"Tested \$IFNAME (\$IFADDR) WEIGHT=\$WEIGHT LOST=\$LOST (m\
    in \$LOSTMINIMUM)\"\
    \n\t\t\$OUTLOG \$MSG\t\
    \n\t}\
    \n}\
    \n\
    \n:foreach WANIF in=\$WANS do={\
    \n\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\t:set IFADDRMASK [ :pick \$WANIF ([:find \$WANIF \"A:\"]+2) ([:find \$W\
    ANIF \"W:\"]-1) ]\
    \n\t:set IFADDR [ :pick \$IFADDRMASK 0 [:find \$IFADDRMASK \"/\" ] ]\
    \n\t:set WEIGHT [ :pick \$WANIF ([:find \$WANIF \"W:\"]+2) ([:find \$WANIF\
    \_\"L:\"]-1) ]\
    \n\t:set LOST [ :pick \$WANIF ([:find \$WANIF \"L:\"]+2) [:len \$WANIF] ]\
    \n\t:set SKIP 0\
    \n\t:set WANCOUNT ( \$WANCOUNT + 1 )\
    \n\tif ( \$LOST > \$LOSTMINIMUM && (\$LOST+\$LOSTTOLERANCE) > \$LOSTMINIMU\
    M ) do={\
    \n\t\t:set WEIGHTSUMM (\$WEIGHTSUMM - \$WEIGHT)\
    \n\t\t:set MSG \"\$IFNAME excluded. Terminating connections, degrading rou\
    te and disabling tun\"\
    \n\t\t\$OUTLOG \$MSG\
    \n### Terminating connections of failed WAN #####\
    \n\t\t/ip firewall connection remove [/ip firewall connection find connect\
    ion-mark=\"WAN-CON-\$IFNAME\"]\
    \n\t\t/ip route set [ /ip route find comment~\"ISP-\$IFNAME\" ] distance=2\
    50\
    \n\t\t/interface gre set [ /interface gre find local-address=\"\$IFADDR\" \
    ] disabled=yes\
    \n\t\t:set LASTCHANGE [/system clock get time]\
    \n\t\t:set LASTCHANGE ([:pick \$LASTCHANGE 0 2] . [:pick \$LASTCHANGE 3 5]\
    \_. [:pick \$LASTCHANGE 6 8])\
    \n\t\t:set SKIP 1\
    \n\t} else={\
    \n\t\t/ip route set [ /ip route find comment~\"ISP-\$IFNAME\" ] distance=\
    \$WANCOUNT\
    \n\t\tif ( [ interface gre find local-address=\"\$IFADDR\" disabled=yes ] \
    = \"\" ) do={\
    \n\t\t\t/interface gre set [ /interface gre find local-address=\"\$IFADDR\
    \" disabled=yes ] disabled=no\
    \n\t\t}\
    \n\t}\
    \n\tif ( \$WEIGHT = 0 ) do={\
    \n\t\t:set SKIP 1\
    \n\t\t:set WANBACKUP \$IFNAME\
    \n\t}\
    \n### Forming new array of WANs #################\
    \n\t:set WANCOUNT ( \$WANCOUNT - \$SKIP )\
    \n\t:set WANARRAY ( \$WANARRAY , \"\$IFNAME A:\$IFADDRMASK W:\$WEIGHT L:\$\
    LOST S:\$SKIP\")\
    \n}\
    \n\
    \n### STEP 1 - Marking incoming connections\
    \n:foreach WANIF in=\$WANARRAY do={\
    \n\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\tif ( [ /ip firewall mangle find comment=\"\$COMMENT \$IFNAME step-1\" \
    ] = \"\" ) do={\
    \n\t\t:set MSG \"1. Marking incoming connections\"\
    \n\t\t\$OUTLOG \$MSG\
    \n\t\t/ip firewall mangle add chain=input in-interface=\$IFNAME action=mar\
    k-connection new-connection-mark=\"WAN-CON-\$IFNAME\" comment=\"\$COMMENT \
    \$IFNAME step-1\"\
    \n\t}\
    \n}\
    \n\
    \n###  STEP 2 - Marking route by connections on output\
    \n:foreach WANIF in=\$WANARRAY do={\
    \n\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\tif ( [ /ip firewall mangle find comment=\"\$COMMENT \$IFNAME step-2\" \
    ] = \"\" ) do={\
    \n\t\t:set MSG \"2. Marking route by connections on output\"\
    \n\t\t\$OUTLOG \$MSG\
    \n\t\t/ip firewall mangle add chain=output connection-mark=\"WAN-CON-\$IFN\
    AME\" action=mark-routing new-routing-mark=\"WAN-RM-\$IFNAME\" comment=\"\
    \$COMMENT \$IFNAME step-2\"\
    \n\t}\
    \n}\
    \n\
    \n### STEP 3 - Allow to access ISP subnet\
    \n:foreach WANIF in=\$WANARRAY do={\
    \n\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\t:set IFADDRMASK [ :pick \$WANIF ([:find \$WANIF \"A:\"]+2) ([:find \$W\
    ANIF \"W:\"]-1) ]\
    \n\tif ( [ /ip firewall mangle find comment=\"\$COMMENT \$IFNAME step-3\" \
    ] = \"\" ) do={\
    \n\t\t:set MSG \"2. Allow to access ISP subnet\"\
    \n\t\t\$OUTLOG \$MSG\
    \n\t\t/ip firewall mangle add chain=prerouting dst-address=\"\$IFADDRMASK\
    \" action=accept in-interface-list=\$LANIFLIST comment=\"\$COMMENT \$IFNAM\
    E step-3\"\
    \n\t}\
    \n}\
    \n\
    \n### STEP 4 - Creating firewall mangle PCC\
    \n:set COUNTER 0\
    \nif ( [ /ip firewall mangle find chain=prerouting action=jump jump-target\
    =pcc comment=\"\$COMMENT\" ] = \"\" ) do={\
    \n\t:set MSG \"4. Creating mangle on incoming for \$IFNAME\"\
    \n\t\$OUTLOG \$MSG\
    \n\t/ip firewall mangle add chain=prerouting action=jump jump-target=pcc c\
    omment=\"\$COMMENT\" in-interface-list=\$LANIFLIST connection-state=new ds\
    t-address-list=!private_nets\
    \n}\t\
    \nif ( [ /ip firewall mangle find chain=pcc comment~\"\$COMMENT PCC-\$WEIG\
    HTSUMM\" ] = \"\" ) do={\
    \n\t:set MSG \"4. Clearing firewall mangle PCC\"\
    \n\t\$OUTLOG \$MSG\
    \n\t/ip firewall mangle remove [/ip firewall mangle find chain=pcc comment\
    ~\"\$COMMENT PCC\" ]\
    \n\t:foreach WANIF in=\$WANARRAY do={\
    \n\t\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\t\t:set WEIGHT [ :pick \$WANIF ([:find \$WANIF \"W:\"]+2) ([:find \$WAN\
    IF \"L:\"]-1) ]\
    \n\t\t:set SKIP [ :pick \$WANIF ([:find \$WANIF \"S:\"]+2) [:len \$WANIF] \
    ]\
    \n\t\tif ( \$SKIP = 0 ) do={\
    \n\t\t\t:for n from=1 to=\$WEIGHT step=1 do={\
    \n\t\t\t\t/ip firewall mangle add chain=pcc per-connection-classifier=\"bo\
    th-addresses-and-ports:\$WEIGHTSUMM/\$COUNTER\" action=mark-connection new\
    -connection-mark=\"WAN-CON-\$IFNAME\" passthrough=yes comment=\"\$COMMENT \
    PCC-\$WEIGHTSUMM step-4\"\
    \n\t\t\t\t:set COUNTER (\$COUNTER+1)\
    \n\t\t\t}\
    \n\t\t\t:set MSG \"4. Created firewall mangle PCC for \$IFNAME x\$WEIGHT\"\
    \n\t\t\t\$OUTLOG \$MSG\
    \n\t\t}\
    \n\t}\
    \n}\
    \n### STEP 5 - Marking route by connections on prerouting\
    \n:foreach WANIF in=\$WANARRAY do={\
    \n\t:set IFNAME [ :pick \$WANIF 0 [:find \$WANIF \" \" ] ]\
    \n\tif ( [ /ip firewall mangle find comment=\"\$COMMENT \$IFNAME step-5\" \
    ] = \"\" ) do={\
    \n\t\t:set MSG \"5. Marking route by connections on prerouting\"\
    \n\t\t\$OUTLOG \$MSG\
    \n\t\t/ip firewall mangle add chain=prerouting connection-mark=\"WAN-CON-\
    \$IFNAME\" in-interface-list=\$LANIFLIST action=mark-routing new-routing-m\
    ark=\"WAN-RM-\$IFNAME\" comment=\"\$COMMENT \$IFNAME step-5\"\
    \n\t}\
    \n}\
    \n"
