/*
 * Copyright (c) 2015, Oracle and/or its affiliates.  All rights reserved.
 *
 * This software is dual-licensed to you under the MIT License (MIT) and 
 * the Universal Permissive License (UPL).  See the LICENSE file in the root
 * directory for license terms.  You may choose either license, or both.
 */

package com.oracle.iot.sample;

import oracle.iot.client.device.async.AsyncDeviceClient;
import oracle.iot.client.device.async.MessageReceipt;
import oracle.iot.client.device.Resource;
import oracle.iot.message.AlertMessage;
import oracle.iot.message.DataMessage;
import oracle.iot.message.HttpRequestMessage;
import oracle.iot.message.HttpResponseMessage;
import oracle.iot.message.Message;
import oracle.iot.message.RequestMessageHandler;
import oracle.iot.message.StatusCode;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Properties;

/**
 * Device Sample simulates a thermometer that periodically sends a
 * temperature reading to the IoT server.
 * <p>This example uses a Properties file named 'config.properties' to
 * store information needed to communicate to the server. The file is
 * expected to be in the directory found by the system property 'user.dir'.
 * The contents of the file are:
 * <pre>
 * device.endpoint.id=&lt;endpoint id from registering the device on the server&gt;
 * device.endpoint.secret=&lt;shared secret from registering the device on the server&gt;
 * server.host=&lt;the name of the IoT server host&gt;
 * server.port=&lt;the HTTP port, if other than default&gt;
 * </pre>
 * If the server requires a certificate for SSL authentication, the certificate
 * should be imported to either the JRE default truststore, or to a truststore
 * created by the user. If the default truststore is not used, the path
 * to the truststore file must be given with the property
 * <span style="font-style:italic">javax.net.ssl.trustStore</span>. For example:
 * <pre>
 *     java -Djavax.net.ssl.trustStore=/some/path/truststore.jks
 * </pre>
 * If the truststore is password protected, then the property
 * <span style="font-style:italic">javax.net.ssl.trustStorePassword</span> must
 * be set to the truststore password.
 * For more information on using the truststore, refer to the
 * <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html">
 * Java Secure Socket Extension (JSSE) Reference Guide</a>
 *
 * <p>
 * There are two resources that can be accessed from an application.
 * <ol>
 *     <li>GET /temperature returns the current temperature value</li>
 *     <li>[GET|POST] /sample_rate returns or sets the interval, in
 *     milliseconds, at which temperature samples are sent to the server.
 *     The value in a POST must be between 10 and 30000, or may be
 *     0 to turn sampling off.</li>
 * </ol>
 * <p>Note that the code is Java SE 1.5 compatible.</p>
 */
public class AsyncDeviceClientSample {

    private final static String ENDPOINT_ID = "device.endpoint.id";
    private final static String SHARED_SECRET = "device.endpoint.secret";
    private final static String SERVER_HOST = "server.host";
    private final static String SERVER_PORT = "server.port";
    private final static String SERVER_CN = "server.cn";
    private final static String DATA_FORMAT = "urn:anaz:iot:device:data:thermometer";
    private final static String ALERT_FORMAT = "urn:anaz:iot:device:alert:thermometer";
    private final static String TEMPERATURE_ATTRIBUTE = "temperature";
    private final static String TEMPERATURE_THRESHOLD_ATTRIBUTE = "temperature_threshold";
    private final static String TEMPERATURE_RESOURCE = "temperature";
    private final static String TEMPERATURE_THRESHOLD_RESOURCE = "temperature/threshold";
    private final static String SAMPLE_RATE_RESOURCE = "sample_rate";

    private Properties configuration;

    // The device client sample sends temperature readings.
    private double temperature;

    // Threshold for temperature before an alert is issued
    private double threshold;

    // The rate, in milliseconds, at which temperature readings are sent
    // to the server. Setting sampleRate to zero effectively turns sampling
    // off. The sample rate may be set via the /sample_rate resource.
    private int sampleRate;

    // The minimum acceptable value for sample_rate, in milliseconds.
    private static final int MIN_SAMPLE_RATE = 10;

    // The maximum acceptable value for sample_rate, in millisecons.
    private static final int MAX_SAMPLE_RATE = 30 * 1000;

    private boolean running = false;

    private AsyncDeviceClientSample() {
        this.temperature = 68.0;
        this.threshold = this.temperature + 12;
        this.sampleRate = 5 * 1000;
        this.running = true;
    }

    /**
     * Get the current temperature value. This method is synchronized because
     * the value might be modified by a request from the server and the handler
     * is called on its own thread.
     * @return the temperature value
     */
    public synchronized double getTemperature() {
        return temperature;
    }

    /**
     * Set the current temperature value. This method is synchronized because
     * the value might be modified by a request from the server and the handler
     * is called on its own thread. This method is private since only the
     * device should modify the temperature value.
     * @param t the new value
     */
    private synchronized void setTemperature(double t) {
        temperature = t;
    }

    /**
     * Get the current temperature threshold value. This method is synchronized
     * because the value might be modified by a request from the server and
     * the handler is called on its own thread.
     * @return the temperature value
     */
    public synchronized double getTemperatureThreshold() {
        return threshold;
    }

    /**
     * Set the current temperature threshold value. This method is synchronized
     * because the value might be modified by a request from the server and
     * the handler is called on its own thread.
     * @param t the new value
     */
    public synchronized void setTemperatureThreshold(double t) {
        threshold = t;
    }

    /**
     * Get the current sampling rate. This method is synchronized because
     * the value might be modified by a request from the server and the handler
     * is called on its own thread.
     * @return the sampling rate
     */
    public synchronized int getSampleRate() {
        return sampleRate;
    }

    /**
     * Get the current sampling rate. This method is synchronized because
     * the value might be modified by a request from the server and the handler
     * is called on its own thread. This method is private since only the
     * device should modify the sampling rate value.
     * @param r the new value
     */
    private synchronized void setSampleRate(int r) {
        sampleRate = r;
    }

    /**
     * Get a configuration property.
     * @param property A property from config.property
     * @return the property value.
     */
    public String getProperty(String property) {
        return configuration.getProperty(property);
    }

    /**
     * @return true if the temperature sending loop is running
     */
    public boolean isRunning() { return running; }

    private void setRunning(boolean running) {
        this.running = running;
    }

    /**
     * Log a message.
     * @param s The message to log
     */
    public static void log(String s) {
        System.out.println(s);
    }

    /**
     * Validate configuration properties.
     * @param configurationFile path to a Properties file.
     * @return true if the configuration file exists, is readable and
     * all properties are valid, else false.
     */
    public boolean configure(String configurationFile) {
        configuration = new Properties();
        InputStream is = null;
        try {
            File file = new File(configurationFile);
            if (!file.exists()) {
                log("Configuration file " + file.getPath() + 
                    " does not exist");
                return false;
            } else if (!file.canRead()) {
                log("Cannot read:" + file.getPath());
                return false;
            }
            is = new FileInputStream(file);
            configuration.load(is);
        } catch (IOException ioe) {
            System.err.println(ioe.toString());
            return false;
        } finally {
            if (is != null) {
                try { is.close(); }
                catch (IOException e) {}
                finally { is = null; }
            }
        }

        final String endpointId = configuration.getProperty(ENDPOINT_ID);
        if (endpointId == null || endpointId.isEmpty()) {
            log("device.endpoint.id not specified in config.properties");
            return false;
        }

        final String sharedSecret = configuration.getProperty(SHARED_SECRET);
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            log("device.endpoint.secret not specified in config.properties");
            return false;
        }

        final String serverHost = configuration.getProperty(SERVER_HOST);
        if (serverHost == null || serverHost.isEmpty()) {
            log("server.host not specified in config.properties");
            return false;
        }

        final String serverPort = configuration.getProperty(SERVER_PORT);
        int port = -1;
        if (serverHost != null &&  !serverHost.isEmpty()) {
            try {
                port = Integer.parseInt(serverPort);
            } catch (NumberFormatException e) {
                log("parsing server.port threw: " + e.toString());
                return false;
            }
        }
        if (port != -1 && (port <= 0 || 65535 < port)) {
            log("server.port not valid: " + 
                port);
            return false;
        }

        final String serverCN = configuration.getProperty(SERVER_CN);
        if (serverCN == null || serverCN.isEmpty()) {
            log("server.cn not specified in config.properties");
            return false;
        }
        // Must be set before any cloud server requests are made.
        // See Client.java.
        System.setProperty("com.oracle.iot.client.server.cn", serverCN);
        return true;
    }

    /**
     * Obtain the private key. If the device has been activated the
     * private key will exist.
     * @return true if the device has its private key, else false.
     */
    private byte[] getPrivateKey() {
        InputStream is = null;
        try {
            System.out.println("\nLoading private key...");
            File file = new File(System.getProperty("user.dir"), "/" + 
                configuration.getProperty(ENDPOINT_ID) + ".bin");
            if (file.exists()) {
                is = new FileInputStream(file);
                byte[] buf = new byte[1024];
                int count = 0;
                int c = -1;
                while ((c = is.read()) != -1) {
                    buf[count++] = (byte)c;
                    if (count == buf.length) {
                        buf = Arrays.copyOf(buf, buf.length + 256);
                    }
                }
                System.out.println("\nPrivate key loaded...");
                return Arrays.copyOf(buf, count);
            } else {
                System.out.println("\nPrivate key file does not exist...");
            }
        } catch (IOException ioe) {
            System.err.println(ioe.getMessage());
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                } finally {
                    is = null;
                }
            }
        }
        return null;
    }

    /**
     * Save the private key to persistent storage
     */
    private void savePrivateKey(byte[] privateKey) {
        OutputStream os = null;
        try {
            File file = new File(System.getProperty("user.dir"), "/" + 
                configuration.getProperty(ENDPOINT_ID) + ".bin");
            if (!file.exists()) {
                file.createNewFile();
                os = new FileOutputStream(file);
                os.write(privateKey);
            }
        } catch (IOException e) {
            log("could not save private key data: " + e.toString());
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ioe) {
                }
            }
        }
    }

    private double getMeasurement(boolean interactive,
                                  double lastTemperatureReading, double delta) {

        double temperature = lastTemperatureReading;
        try {

            System.out.println("\nGetting Measurement...");

            if (interactive) {
                BufferedReader br = 
                    new BufferedReader(new InputStreamReader(System.in));
                System.out.print(
                    "\nEnter a positive temperature or any other input to quit." +
                    "\nEnter a positive temperature: ");
                String input = br.readLine();
                if (input == null) {
                    setRunning(false);
                }
                try {
                    temperature = Double.parseDouble(input);
                } catch (NumberFormatException nfe) {
                    // Quit on any non number input
                    setRunning(false);
                }
            } else {
                int delay = getSampleRate();
                if (delay > 0) {
                    Thread.sleep(delay);
                } else {
                    System.out.println("Waiting for sample rate to be non-zero");
                    do {
                        Thread.sleep(1000);
                    } while ((delay = getSampleRate()) <= 0);
                }
                temperature = lastTemperatureReading + delta;
            }
        } catch (Exception e) {
            // Nothing important to catch here
        }
        return temperature;
    }

    private static class TemperatureHandler implements RequestMessageHandler {

        private final AsyncDeviceClientSample deviceClientSample;
        private TemperatureHandler(AsyncDeviceClientSample deviceClientSample) {
            this.deviceClientSample = deviceClientSample;
        }

        @Override
        public HttpResponseMessage handleRequest(HttpRequestMessage request) throws Exception {

            final HttpResponseMessage.Builder builder = new HttpResponseMessage.Builder()
                    .source(request.getDestination())
                    .destination(request.getSource())
                    .requestId(request.getId());

            final String method = request.getMethod().toUpperCase();
            if ("GET".equals(method)) {
                builder.statusCode(StatusCode.OK)
                        .body("{\"temperature\" : " + deviceClientSample.getTemperature() + "}");
            } else {
                builder.statusCode(StatusCode.METHOD_NOT_ALLOWED);
            }

            HttpResponseMessage responseMessage  = builder.build();
            log("HTTP " + method + " " + TEMPERATURE_RESOURCE
                    + " returns " + responseMessage.getStatusCode());

            return responseMessage;
        }
    }

    private static class TemperatureThresholdHandler implements RequestMessageHandler {

        private final AsyncDeviceClientSample deviceClientSample;
        private TemperatureThresholdHandler(AsyncDeviceClientSample deviceClientSample) {
            this.deviceClientSample = deviceClientSample;
        }

        @Override
        public HttpResponseMessage handleRequest(HttpRequestMessage request) throws Exception {

            final HttpResponseMessage.Builder builder = new HttpResponseMessage.Builder()
                    .source(request.getDestination())
                    .destination(request.getSource())
                    .requestId(request.getId());

            final String method = request.getMethod().toUpperCase();
            if ("GET".equals(method)) {
                builder.statusCode(StatusCode.OK)
                        .body("{\"temperature_threshold\" : " + deviceClientSample.getTemperatureThreshold() + "}");
            } else if ("POST".equals(method) || "PUT".equals(method)) {
                String body = request.getBodyString();
                try {
                    double value = Double.valueOf(body);
                    deviceClientSample.setTemperatureThreshold(value);
                    log("temperature threshold set to " + value);
                    builder.statusCode(StatusCode.ACCEPTED);
                } catch (NumberFormatException e) {
                    builder.statusCode(StatusCode.NOT_ACCEPTABLE);
                }
            } else {
                builder.statusCode(StatusCode.METHOD_NOT_ALLOWED);
            }

            HttpResponseMessage responseMessage  = builder.build();
            log("HTTP " + method + " " + TEMPERATURE_THRESHOLD_RESOURCE
                    + " returns " + responseMessage.getStatusCode());

            return responseMessage;
        }
    }

    private static class SampleRateHandler implements RequestMessageHandler {

        private final AsyncDeviceClientSample deviceClientSample;
        private SampleRateHandler(AsyncDeviceClientSample deviceClientSample) {
            this.deviceClientSample = deviceClientSample;
        }

        @Override
        public HttpResponseMessage handleRequest(HttpRequestMessage request) throws Exception {

            final HttpResponseMessage.Builder builder = new HttpResponseMessage.Builder()
                    .source(request.getDestination())
                    .destination(request.getSource())
                    .requestId(request.getId());

            final String method = request.getMethod().toUpperCase();
            if ("GET".equals(method)) {
                builder.statusCode(StatusCode.OK)
                        .body("{\"sampling_rate\" : " + deviceClientSample.getSampleRate() + "}");
            } else if ("POST".equals(method) || "PUT".equals(method)) {
                String body = request.getBodyString();
                try {
                    int value = Integer.valueOf(body);
                    if (value == 0 || (MIN_SAMPLE_RATE <= value && value <= MAX_SAMPLE_RATE)) {
                        deviceClientSample.setSampleRate(value);
                        log("sample rate set to " + value);
                        builder.statusCode(StatusCode.ACCEPTED);
                    } else {
                        builder.statusCode(StatusCode.NOT_ACCEPTABLE);
                    }
                } catch (NumberFormatException e) {
                    builder.statusCode(StatusCode.NOT_ACCEPTABLE);
                }
            } else {
                builder.statusCode(StatusCode.METHOD_NOT_ALLOWED);
            }

            HttpResponseMessage responseMessage = builder.build();
            log("HTTP " + method + " " + SAMPLE_RATE_RESOURCE
                    + " returns " + responseMessage.getStatusCode());

            return responseMessage;
        }
    }

    private static final MessageReceipt.NotificationHandler MESSAGE_TRACKING_NOTIFICATION_HANDLER =
            new MessageReceipt.NotificationHandler() {
                @Override
                public void changed(MessageReceipt observable, MessageReceipt.Status oldValue, MessageReceipt.Status newValue) {
                    final Message message = observable.getMessage();
                    final String clientId = message.getClientId();
                    System.out.println("Message " + clientId + " changed status from " + oldValue + " to " + newValue);

                    if (newValue == MessageReceipt.Status.SUCCESS
                            || newValue == MessageReceipt.Status.FAILURE) {
                        // Done listening to this message status
                        observable.setNotificationHandler(null);
                    }
                }
            };

    public static void main(String[] args) {

        // Using JDK 8 requires the application to set the
        // TLS version to "TLSv1"
        System.setProperty("https.protocols", "TLSv1");

        AsyncDeviceClientSample dcs = new AsyncDeviceClientSample();
        try {

            // This example uses a Properties file to store information
            // needed to communicate to the server
            //
            // device.endpoint.id=
            // device.endpoint.secret=
            // server.certificate=
            // server.host=
            // server.port=
            final String configurationFile = 
                System.getProperty("user.dir") + "/config.properties";

            // Obtain the necessary information to connect to the server
            // from the configuration file, device's registered endpoint id,
            // and shared secret, and creat an X509 certificate required to
            // connect.
            System.out.println("\nConfiguring...");
            if (!dcs.configure(configurationFile)) {
                System.exit(-1);
            }

            // Create the device client instance
            System.out.println("\nCreating the device instance...");
            AsyncDeviceClient deviceClient =
                    new AsyncDeviceClient(dcs.getProperty(SERVER_HOST),
                            Integer.parseInt(dcs.getProperty(SERVER_PORT)),
                            dcs.getProperty(ENDPOINT_ID));


            // If the device has activated before the private
            // key has been saved and can be obtained from the
            // persistent store. 
            byte[] privateKey = dcs.getPrivateKey();

            // The existence of the stored private key indicates
            // that the device has been activated.
            boolean activated = privateKey != null;

            if (!activated) {
                // If the device has not been activated, connect to the server
                // using client-credentials and activate the client to
                // obtain the private key. The private key is then persisted.
                System.out.println("\nConnecting with client-credentials...");
                try {
                    System.out.println("\nActivating...");
                    // activate will not return null, but will throw an
                    // AlreadyActivatedException if the client is not connected
                    // or the device is already activated.
                    privateKey = deviceClient.activate(dcs.getProperty(SHARED_SECRET));

                    System.out.println("\nSaving private key...");
                    dcs.savePrivateKey(privateKey);
                } catch (IllegalStateException aae) {
                    log("The device has already been activated, but there is no private key");
                    log("Enroll a new device and try again.");
                    System.exit(-1);
                }
            } else {
                // Authenticate with, and connect to, the server
                System.out.println("\nConnecting with client-assertion...");
                deviceClient.authenticate(privateKey);
            }

            // register handler for resources, if any
            final Resource temperatureResource = new Resource.Builder()
                    .name("temperature")
                    .endpointName(dcs.getProperty(ENDPOINT_ID))
                    .method(Resource.Method.GET)
                    .path(TEMPERATURE_RESOURCE)
                    .build();
            deviceClient.registerRequestHandler(temperatureResource, new TemperatureHandler(dcs));

            final Resource temperatureThresholdResource = new Resource.Builder()
                    .name("temperature-threshold")
                    .endpointName(dcs.getProperty(ENDPOINT_ID))
                    .method(Resource.Method.GET)
                    .method(Resource.Method.PUT)
                    .method(Resource.Method.POST)
                    .path(TEMPERATURE_THRESHOLD_RESOURCE)
                    .build();
            deviceClient.registerRequestHandler(temperatureThresholdResource, new TemperatureThresholdHandler(dcs));

            final Resource sampleRateResource = new Resource.Builder()
                    .name("sample-rate")
                    .endpointName(dcs.getProperty(ENDPOINT_ID))
                    .method(Resource.Method.GET)
                    .method(Resource.Method.PUT)
                    .method(Resource.Method.POST)
                    .path(SAMPLE_RATE_RESOURCE)
                    .build();
            deviceClient.registerRequestHandler(sampleRateResource, new SampleRateHandler(dcs));

            // If not in interactive mode, this loop simulates temperature readings
            // by changing the temperature by delta degrees for each call to
            // getMesaurement. The temperature increases until the upper threshold
            // is reached, then decreases until the lower threshold is reached.
            double temperature = dcs.getTemperature();
            final double lowerThreshold = temperature;
            double delta = 2.0;

            while (dcs.isRunning()) {

                // If there are any args, prompt for a temperature
                temperature = dcs.getMeasurement(args.length > 0, temperature, delta);
                if (!dcs.isRunning()) break;

                dcs.setTemperature(temperature);

                double upperThreshold = dcs.getTemperatureThreshold();
                if (lowerThreshold < temperature && temperature < upperThreshold) {
                    // Use a random number to send messages of
                    // differing priority.
                    double p = Math.random();

                    // The available priorities are
                    //     Message.Priorit.HIGH
                    //     Message.Priorit.HIGHEST
                    //     Message.Priorit.LOW
                    //     Message.Priorit.LOWEST
                    //     Message.Priorit.MEDIUM
                    Message.Priority priority =
                            Message.Priority.values()[(int) Math.round(4 * p)];

                    // Create a DataMessage
                    DataMessage.Builder builder = new DataMessage.Builder();

                    // Add message information.
                    // Note that Reliability.GUARANTEED_DELIVERY is not currently supported
                    builder.format(DATA_FORMAT)
                            .source(dcs.getProperty(ENDPOINT_ID))
                            .dataItem(TEMPERATURE_ATTRIBUTE, temperature)
                            .reliability(Message.Reliability.BEST_EFFORT)
                            .priority(priority);

                    DataMessage msg = builder.build();

                    System.out.println("\nSending message...");
                    MessageReceipt receipt = deviceClient.sendMessage(msg);
                    receipt.setNotificationHandler(MESSAGE_TRACKING_NOTIFICATION_HANDLER);

                    System.out.println("\n" + msg + "\n");

                } else {
                    // reverse the direction of simulated temperature readings
                    delta = -delta;

                    final boolean over = temperature >= upperThreshold;
                    final String description =
                            "Temperature " +
                             (over ? "over" : "under") +
                             " threshold";

                    AlertMessage.Builder builder = new AlertMessage.Builder();
                    builder.format(ALERT_FORMAT)
                            .source(dcs.getProperty(ENDPOINT_ID))
                            .description(description)
                            .dataItem(TEMPERATURE_THRESHOLD_ATTRIBUTE, over ? upperThreshold : lowerThreshold)
                            .dataItem(TEMPERATURE_ATTRIBUTE, temperature)
                            .severity(AlertMessage.Severity.CRITICAL);

                    AlertMessage msg = builder.build();

                    System.out.println("\n"  + description + ". Sending alert message...");
                    MessageReceipt receipt = deviceClient.sendMessage(msg);
                    receipt.setNotificationHandler(MESSAGE_TRACKING_NOTIFICATION_HANDLER);

                    System.out.println("\n" + msg + "\n");
                }
            }

            // unregister handlers for resources
            System.out.println("unregisterRequestHandler " + TEMPERATURE_RESOURCE);
            deviceClient.unregisterRequestHandler(temperatureResource);

            System.out.println("unregisterRequestHandler " + TEMPERATURE_THRESHOLD_RESOURCE);
            deviceClient.unregisterRequestHandler(temperatureThresholdResource);

            System.out.println("unregisterRequestHandler " + SAMPLE_RATE_RESOURCE);
            deviceClient.unregisterRequestHandler(sampleRateResource);

            // stop sending and receiving messages, and release resources
            System.out.println("Close deviceClient");
            deviceClient.close();

        } catch (IllegalStateException e) {
            // Just means the device was already activated
            AsyncDeviceClientSample.log(e.toString() +
                "\nNo private key.");
            System.exit(-1);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
