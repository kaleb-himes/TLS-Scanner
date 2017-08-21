/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import static de.rub.nds.tlsscanner.probe.TLSProbe.LOGGER;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ExtensionProbe extends TLSProbe {

    private final ScannerConfig scannerConfig;

    private final List<ProtocolVersion> protocolVersions;

    public ExtensionProbe(ScannerConfig config) {
        super(ProbeType.EXTENSION, config);
        protocolVersions = new LinkedList<>();
        protocolVersions.add(ProtocolVersion.TLS10);
        protocolVersions.add(ProtocolVersion.TLS11);
        protocolVersions.add(ProtocolVersion.TLS12);
        scannerConfig = config;
    }

    @Override
    public ProbeResult call() {
        List<Config> extensionsToBeTested = new LinkedList<>();
        extensionsToBeTested.add(createEncryptThenMacConfig());
        extensionsToBeTested.add(createExtendedMasterSecretConfig());
        extensionsToBeTested.addAll(createMaxFragmentLengthConfigs());
        extensionsToBeTested.add(createCertTypeConfig());
        extensionsToBeTested.add(createClientAuthzConfig());
        //extensionsToBeTested.add(createClientCertTypeConfig());
        extensionsToBeTested.add(createClientCertUrlConfig());
        extensionsToBeTested.add(createRenegotiationInfoConfig());
        extensionsToBeTested.add(createSessionTicketConfig());
        extensionsToBeTested.add(createTruncatedHmacConfig());
        extensionsToBeTested.add(createUseSrtpConfig());
        extensionsToBeTested.addAll(createTokenBindingConfigs());

        List<ResultValue> resultList = new LinkedList<>();
        List<TLSCheck> checkList = new LinkedList<>();

        StringBuilder csvResult = new StringBuilder();
        csvResult.append(scannerConfig.getClientDelegate().getHost());
        csvResult.append(',');

        boolean[] results = new boolean[28];

        for (boolean bool : results) {
            bool = false;
        }

        for (Config config : extensionsToBeTested) {
            TlsContext tlsContext = new TlsContext(config);
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, tlsContext);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                LOGGER.warn("Encountered exception while executing WorkflowTrace!");
                LOGGER.debug(ex);
            }
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, tlsContext.getWorkflowTrace())) {

                HandshakeMessage serverHelloMessage = WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, tlsContext.getWorkflowTrace());

                List<ExtensionMessage> extensionMessages = new LinkedList<>();
                extensionMessages = serverHelloMessage.getExtensions();

                for (ExtensionMessage message : extensionMessages) {

                    if (message instanceof EncryptThenMacExtensionMessage) {
                        results[0] = true;
                    }
                    if (message instanceof ExtendedMasterSecretExtensionMessage) {
                        results[1] = true;
                    }
                    if (message instanceof MaxFragmentLengthExtensionMessage) {
                        if (MaxFragmentLength.getMaxFragmentLength(((MaxFragmentLengthExtensionMessage) message).getMaxFragmentLength().getValue()[0]) == MaxFragmentLength.TWO_9) {
                            results[2] = true;
                        }
                        if (MaxFragmentLength.getMaxFragmentLength(((MaxFragmentLengthExtensionMessage) message).getMaxFragmentLength().getValue()[0]) == MaxFragmentLength.TWO_10) {
                            results[3] = true;
                        }
                        if (MaxFragmentLength.getMaxFragmentLength(((MaxFragmentLengthExtensionMessage) message).getMaxFragmentLength().getValue()[0]) == MaxFragmentLength.TWO_11) {
                            results[4] = true;
                        }
                        if (MaxFragmentLength.getMaxFragmentLength(((MaxFragmentLengthExtensionMessage) message).getMaxFragmentLength().getValue()[0]) == MaxFragmentLength.TWO_12) {
                            results[5] = true;
                        }
                    }
                    if (message instanceof CertificateTypeExtensionMessage) {
                        results[6] = true;
                    }
                    if (message instanceof ClientAuthzExtensionMessage) {
                        results[7] = true;
                    }
                    if (message instanceof ClientCertificateUrlExtensionMessage) {
                        results[8] = true;
                    }
                    if (message instanceof RenegotiationInfoExtensionMessage) {
                        results[9] = true;
                    }
                    if (message instanceof SessionTicketTLSExtensionMessage) {
                        results[10] = true;
                    }
                    if (message instanceof TruncatedHmacExtensionMessage) {
                        results[11] = true;
                    }
                    if (message instanceof SrtpExtensionMessage) {
                        results[12] = true;
                    }
                    if (message instanceof TokenBindingExtensionMessage) {
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_1) {
                            results[13] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_2) {
                            results[14] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_3) {
                            results[15] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_4) {
                            results[16] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_5) {
                            results[17] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_6) {
                            results[18] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_7) {
                            results[19] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_8) {
                            results[20] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_9) {
                            results[21] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_10) {
                            results[22] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_11) {
                            results[23] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_12) {
                            results[24] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_13) {
                            results[25] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_14) {
                            results[26] = true;
                        }
                        if (TokenBindingVersion.getExtensionType(((TokenBindingExtensionMessage) message).getTokenbindingVersion().getValue()) == TokenBindingVersion.DRAFT_15) {
                            results[27] = true;
                        }
                    }
                }

            } else {
                LOGGER.warn("Server did not send ServerHello");
                LOGGER.warn(tlsContext.getWorkflowTrace().toString());
                if (tlsContext.isReceivedFatalAlert()) {
                    LOGGER.warn("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) WorkflowTraceUtil.getFirstReceivedMessage(ProtocolMessageType.ALERT, tlsContext.getWorkflowTrace());
                    LOGGER.warn("Type:" + alert.toString());

                }
            }
        }

        for (int i = 0; i < results.length - 1; i++) {
            if (results[i]) {
                csvResult.append("1,");
            } else {
                csvResult.append("0,");
            }
        }
        if (results[27]) {
            csvResult.append("1\r\n");
        } else {
            csvResult.append("0\r\n");
        }
        resultList.add(new ResultValue("", csvResult.toString()));
        return new ProbeResult(getType(), resultList, checkList);
    }

    public Config createStandardConfig() {
        Config config = getConfig().createConfig();
        try {
            config.setDefaultClientSupportedCiphersuites(Arrays.asList(CipherSuite.values()));
            config.setHighestProtocolVersion(ProtocolVersion.TLS12);
            config.setEnforceSettings(true);
            config.setAddServerNameIndicationExtension(false);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgrorithmsExtension(true);
            config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopActionsAfterFatal(true);
            List<NamedCurve> namedCurves = new LinkedList<>();
            namedCurves.addAll(Arrays.asList(NamedCurve.values()));
            config.setNamedCurves(namedCurves);
        } catch (Exception ex) {
            LOGGER.warn("Config Erstellung ging schief.");
            LOGGER.warn(ex);
            ex.printStackTrace();
        }

        return config;
    }

    public Config createEncryptThenMacConfig() {
        Config config = createStandardConfig();
        config.setAddEncryptThenMacExtension(true);
        return config;
    }

    public Config createExtendedMasterSecretConfig() {
        Config config = createStandardConfig();
        config.setAddExtendedMasterSecretExtension(true);
        return config;
    }

    public Collection<Config> createMaxFragmentLengthConfigs() {
        Collection<Config> collection = new LinkedList<>();

        Config config1 = createStandardConfig();
        config1.setAddMaxFragmentLengthExtenstion(true);
        config1.setMaxFragmentLength(MaxFragmentLength.TWO_9);
        Config config2 = createStandardConfig();
        config2.setAddMaxFragmentLengthExtenstion(true);
        config2.setMaxFragmentLength(MaxFragmentLength.TWO_10);
        Config config3 = createStandardConfig();
        config3.setAddMaxFragmentLengthExtenstion(true);
        config3.setMaxFragmentLength(MaxFragmentLength.TWO_11);
        Config config4 = createStandardConfig();
        config4.setAddMaxFragmentLengthExtenstion(true);
        config4.setMaxFragmentLength(MaxFragmentLength.TWO_12);

        collection.add(config1);
        collection.add(config2);
        collection.add(config3);
        collection.add(config4);
        return collection;
    }

    public Config createCertTypeConfig() {
        Config config = createStandardConfig();
        config.setAddCertificateTypeExtension(true);
        config.setCertificateTypeDesiredTypes(Arrays.asList(CertificateType.values()));
        return config;
    }

    public Config createClientAuthzConfig() {
        Config config = createStandardConfig();
        config.setAddClientAuthzExtension(true);
        List<AuthzDataFormat> dataFormat = Arrays.asList(AuthzDataFormat.values());
        config.setClientAuthzExtensionDataFormat(dataFormat);
        return config;
    }

    public Config createClientCertTypeConfig() {
        Config config = createStandardConfig();
        config.setAddClientCertificateTypeExtension(true);
        config.setClientCertificateTypeDesiredTypes(Arrays.asList(CertificateType.values()));
        return config;
    }

    public Config createClientCertUrlConfig() {
        Config config = createStandardConfig();
        config.setAddClientCertificateUrlExtension(true);
        return config;
    }

    public Config createRenegotiationInfoConfig() {
        Config config = createStandardConfig();
        config.setAddRenegotiationInfoExtension(true);
        return config;
    }

    public Config createServerAuthzConfig() {
        Config config = createStandardConfig();
        config.setAddServerAuthzExtension(true);
        List<AuthzDataFormat> dataFormat = Arrays.asList(AuthzDataFormat.values());
        config.setServerAuthzExtensionDataFormat(dataFormat);
        return config;
    }

    public Config createSessionTicketConfig() {
        Config config = createStandardConfig();
        config.setAddSessionTicketTLSExtension(true);
        return config;
    }

    public Config createTruncatedHmacConfig() {
        Config config = createStandardConfig();
        config.setAddTruncatedHmacExtension(true);
        return config;
    }

    public Config createUseSrtpConfig() {
        Config config = createStandardConfig();
        config.setAddSRTPExtension(true);
        config.setSecureRealTimeTransportProtocolProtectionProfiles(Arrays.asList(SrtpProtectionProfiles.values()));
        return config;
    }

    public Collection<Config> createTokenBindingConfigs() {
        Collection<Config> collection = new LinkedList<>();

        Config config1 = createStandardConfig();
        config1.setAddTokenBindingExtension(true);
        config1.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_1);
        Config config2 = createStandardConfig();
        config2.setAddTokenBindingExtension(true);
        config2.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_2);
        Config config3 = createStandardConfig();
        config3.setAddTokenBindingExtension(true);
        config3.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_3);
        Config config4 = createStandardConfig();
        config4.setAddTokenBindingExtension(true);
        config4.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_4);
        Config config5 = createStandardConfig();
        config5.setAddTokenBindingExtension(true);
        config5.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_5);
        Config config6 = createStandardConfig();
        config6.setAddTokenBindingExtension(true);
        config6.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_6);
        Config config7 = createStandardConfig();
        config7.setAddTokenBindingExtension(true);
        config7.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_7);
        Config config8 = createStandardConfig();
        config8.setAddTokenBindingExtension(true);
        config8.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_8);
        Config config9 = createStandardConfig();
        config9.setAddTokenBindingExtension(true);
        config9.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_9);
        Config config10 = createStandardConfig();
        config10.setAddTokenBindingExtension(true);
        config10.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_10);
        Config config11 = createStandardConfig();
        config11.setAddTokenBindingExtension(true);
        config11.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_11);
        Config config12 = createStandardConfig();
        config12.setAddTokenBindingExtension(true);
        config12.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_12);
        Config config13 = createStandardConfig();
        config13.setAddTokenBindingExtension(true);
        config13.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_13);
        Config config14 = createStandardConfig();
        config14.setAddTokenBindingExtension(true);
        config14.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_14);
        Config config15 = createStandardConfig();
        config15.setAddTokenBindingExtension(true);
        config15.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_15);

        collection.add(config1);
        collection.add(config2);
        collection.add(config3);
        collection.add(config4);
        collection.add(config5);
        collection.add(config6);
        collection.add(config7);
        collection.add(config8);
        collection.add(config9);
        collection.add(config10);
        collection.add(config11);
        collection.add(config12);
        collection.add(config13);
        collection.add(config14);
        collection.add(config15);
        return collection;
    }
}
