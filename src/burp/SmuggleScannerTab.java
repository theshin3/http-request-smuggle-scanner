package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.util.*;
import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;

public class SmuggleScannerTab implements ITab{

    private JPanel mainPanel;
    private  JTextArea txtInput;
    private static JTextArea txtLog;
    private  JButton btnScan;
    private  boolean running = false;
    private  Scan scanner;
    public SmuggleScannerTab(Scan scanner) {
        initUI();
        this.scanner = scanner;
    }
    public static void log(String content){
        txtLog.append(content + "\n");
        try {
            FileWriter fw = new FileWriter("smuggle.log", true);
            fw.write(content);
            fw.close();
        } catch (IOException e) {
//            e.printStackTrace();
        }
    }
    public JPanel initUI() {
        mainPanel = new JPanel(new GridLayout(1, 2));
        //Create the input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        //header
        JPanel buttonsPanel = new JPanel(new FlowLayout());
        JButton btnLoadFile = new JButton("Load...");
        btnLoadFile.addActionListener(loadFileActionListener());
        btnScan = new JButton("Scan");
        btnScan.addActionListener(scanActionListener());
        buttonsPanel.add(btnLoadFile);
        buttonsPanel.add(btnScan);
        inputPanel.add(buttonsPanel, BorderLayout.NORTH);

        JPanel inputTextWrapper = new JPanel(new BorderLayout());
        txtInput = new JTextArea();
        JScrollPane inputScrollPane = new JScrollPane(txtInput);
        inputTextWrapper.add(inputScrollPane, BorderLayout.CENTER);
        inputPanel.add(inputTextWrapper, BorderLayout.CENTER);
        //Create the log panel
        JPanel logPanel = new JPanel(new BorderLayout());
        // Header
        JPanel logHeaderPanel = new JPanel();
        JButton btnSaveLog = new JButton("Save Log");
        btnSaveLog.addActionListener(saveLogActionListener());
        logHeaderPanel.add(btnSaveLog);
        logPanel.add(logHeaderPanel, BorderLayout.NORTH);
        //log
        JPanel logTextWrapper = new JPanel(new BorderLayout());
        txtLog = new JTextArea("");
        JScrollPane logScrollPane = new JScrollPane(txtLog);
        logTextWrapper.add(logScrollPane, BorderLayout.CENTER);
        logPanel.add(logTextWrapper, BorderLayout.CENTER);

        mainPanel.add(inputPanel);
        mainPanel.add(logPanel);
        return mainPanel;
    }

    public  String [] parseUrl(String url) throws MalformedURLException {
        URL u = new URL(url);
        String host = u.getHost();
        int port = u.getPort();
        String protocol = u.getProtocol();
        if(port == -1){
            port = 80;
            if(protocol.equals("https")){
                port = 443;
            }
        }
        return new String[]{host, Integer.toString(port), protocol};
    }

    private void scan(String input){
        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if(config == null){
            return;
        }
        running = true;
        String[] urls = input.split("\r?\n");
        ArrayList<Target> targets = new ArrayList<>();
        for(String url: urls){
            try {
                String[] urlStrings = parseUrl(url);
                String host = urlStrings[0];
                String port = urlStrings[1];
                String protocol = urlStrings[2];
                targets.add(new Target(host, Integer.parseInt(port), protocol));
//                        loader.scan(host, Integer.parseInt(port), ssl);
//                        log("Complete Scan: " + host + ":" + port);
            } catch (MalformedURLException ex) {
                Utilities.log("URL parser error: " + url);
            } catch (Exception ex){
                ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
                PrintStream ps = new PrintStream(baos);
                ex.printStackTrace(ps);
                String error = new String(baos.toByteArray());
                log(error);
            }
        }
        BulkScan2 bulkScan2 = new BulkScan2(scanner, targets, config);
        (new Thread(bulkScan2)).start();
        running = false;
    }
    private ActionListener scanActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!running){
                    String input = txtInput.getText();
                    if(input.trim().equals("")){
                        log("Input empty!");
                        return;
                    }

                    scan(input);
                }

            }
        };
    }

    private ActionListener saveLogActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String content = txtLog.getText();
                if(content.equals("")){
                    return;
                }
                JFileChooser fileChooser = new JFileChooser();
                int option = fileChooser.showSaveDialog(mainPanel);
                if (option == JFileChooser.APPROVE_OPTION){
                    File file = fileChooser.getSelectedFile();
                    try {
                        FileWriter pw = new FileWriter(file);
                        pw.write(content);
                        pw.close();
                    } catch (IOException ex) {
//                        ex.printStackTrace();
                    }
                }
            }
        };
    }

    private ActionListener loadFileActionListener() {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int option = fileChooser.showOpenDialog(mainPanel);
                if(option == JFileChooser.APPROVE_OPTION){
                    File file = fileChooser.getSelectedFile();
                    try {
                        String input = new String(Files.readAllBytes(file.toPath()));
                        txtInput.setText(input);
                    } catch (IOException ex) {
//                        Logger.getLogger(SmugglerTab.class.getName()).log(Level.SEVERE, null, ex);
                        log("File not found");
                    }
                }
            }
        };
    }

    @Override
    public String getTabCaption() {
        return "Smuggling Scanner";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}

class BulkScan2 implements Runnable  {
    private ArrayList<Target> targets;
    private Scan scan;
    private ConfigurableSettings config;

    BulkScan2(Scan scan, ArrayList<Target> targets) {
        this.scan = scan;
        this.targets = targets;
        this.config = Utilities.globalSettings;
    }

    BulkScan2(Scan scan, ArrayList<Target> targets, ConfigurableSettings config) {
        this.scan = scan;
        this.targets = targets;
        this.config = config;
    }

    public void run() {
        ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+targets.size()+" tasks to queue of "+queueSize);
        queueSize += targets.size();
        int thread_count = taskEngine.getCorePoolSize();

        int cache_size = queueSize; //thread_count;

        Set<String> keyCache = new HashSet<>();

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        int queued = 0;

        // every pass adds at least one item from every host
        while(!targets.isEmpty()) {
            Utilities.log("Loop "+i++);
            Iterator<Target> left = targets.iterator();
            while (left.hasNext()) {
                Target target = left.next();
                String host = target.host;
                if (cache.contains(host)) {
                    remainingHosts.add(host);
                    continue;
                }

                cache.add(host);
                left.remove();
                Utilities.log("Adding request on "+host+" to queue");
                queued++;
                taskEngine.execute(new BulkScanItem2(scan, target));
            }

            cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
        }
        Utilities.out("Queued " + queued + " attacks");
    }
}

class BulkScanItem2 implements Runnable {

    private Target target;
    private final Scan scanner;

    BulkScanItem2(Scan scanner, Target target) {
        this.target = target;
        this.scanner = scanner;
    }

    public void run() {
        scanner.doScan(target.request(), target.service());
        ScanPool engine = BulkScanLauncher.getTaskEngine();
        long done = engine.getCompletedTaskCount()+1;
        Utilities.out("Completed "+ target.host + " of "+(engine.getQueue().size()+done));
    }
}

class Target{
    public String host;
    public int port;
    public String protocol;

    public Target(String host, int port, String protocol){
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }

    public byte[] request(){
        String template = "POST / HTTP/1.1\r\nHost: %d\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        byte[] request = template.replace("%d", host).getBytes();
        return  request;
    }

    public IHttpService service(){
        boolean ssl = protocol.equals("https")? true: false;
        IHttpService service = Utilities.callbacks.getHelpers().buildHttpService(host, port, ssl);
        return  service;
    }
}