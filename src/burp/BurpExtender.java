package burp;

import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "HTTP Request Smuggle Scanner";
    private static final String version = "1.04";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        ChunkContentScan scanner = new ChunkContentScan("Smuggle probe");
        // register scanner tab
        SmuggleScannerTab smugglerTab = new SmuggleScannerTab(scanner);
        callbacks.customizeUiComponent(smugglerTab.getUiComponent());
        callbacks.addSuiteTab(smugglerTab);
        Utils.setBurpPresent(callbacks);
//        Utilities.out("Loaded " + name + " v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}

