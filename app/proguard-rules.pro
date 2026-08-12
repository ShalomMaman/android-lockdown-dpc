-keep class com.example.lockdowndpc.admin.LockdownAdminReceiver { *; }
-keep class com.example.lockdowndpc.receivers.** { *; }
# The pilot artifact gate reads these exact compiled fields from DEX. Keeping
# this tiny generated class makes channel verification structural rather than a
# fragile whole-file byte/string search.
-keep class com.example.lockdowndpc.BuildConfig { *; }
