target extended-remote localhost:3333
monitor arm semihosting enable
load

# 
# break post_init
# command
# echo _gDevice.mIface.mIfaceCFG.devtype\n
# p _gDevice.mIface.mIfaceCFG.devtype
# echo _gDevice.mIface.mIfaceCFG\n
# p * _gDevice.mIface.mIfaceCFG
# end
# break atcab_get_device_type
# command
# echo g_atcab_device\n
# p g_atcab_device
# end

continue
