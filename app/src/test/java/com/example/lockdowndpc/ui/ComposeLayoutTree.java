package com.example.lockdowndpc.ui;

import androidx.compose.ui.layout.LayoutInfo;
import androidx.compose.ui.semantics.SemanticsInfo;
import java.util.List;

/** Isolates the Compose internal accessor needed for nodes without accessibility semantics. */
final class ComposeLayoutTree {
    private ComposeLayoutTree() {}

    static List<? extends LayoutInfo> children(LayoutInfo node) {
        return ((SemanticsInfo) node).getChildrenInfo();
    }
}
