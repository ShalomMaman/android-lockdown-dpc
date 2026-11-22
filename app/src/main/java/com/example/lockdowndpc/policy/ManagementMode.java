package com.example.lockdowndpc.policy;

public enum ManagementMode {
    UNDECIDED,
    LOCAL_PIN,
    ENROLLING,
    REMOTE;

    public boolean usesLocalPolicy() {
        return this == UNDECIDED || this == LOCAL_PIN;
    }
}
