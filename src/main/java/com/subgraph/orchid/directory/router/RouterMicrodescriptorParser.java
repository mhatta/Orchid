package com.subgraph.orchid.directory.router;

import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParsingResultHandler;

public class RouterMicrodescriptorParser implements DocumentParser<RouterMicrodescriptor>{

	
	private final DocumentFieldParser fieldParser;
	
	private RouterMicrodescriptorImpl currentDescriptor;
	private DocumentParsingResultHandler<RouterMicrodescriptor> resultHandler;
	
	public RouterMicrodescriptorParser(DocumentFieldParser fieldParser) {
		this.fieldParser = fieldParser;
		this.fieldParser.setHandler(createParsingHandler());
	}

	private DocumentParsingHandler createParsingHandler() {
		return new DocumentParsingHandler() {
			public void parseKeywordLine() {
				processKeywordLine();
			}
			public void endOfDocument() { 
				if(currentDescriptor != null) {
					finalizeDescriptor(currentDescriptor);
				}
			}
		};
	}
	
	public boolean parse(DocumentParsingResultHandler<RouterMicrodescriptor> resultHandler) {
		this.resultHandler = resultHandler;
		try {
			fieldParser.processDocument();
			return true;
		} catch(TorParsingException e) {
			resultHandler.parsingError(e.getMessage());
			return false;
		}
	}

	public DocumentParsingResult<RouterMicrodescriptor> parse() {
		final BasicDocumentParsingResult<RouterMicrodescriptor> result = new BasicDocumentParsingResult<RouterMicrodescriptor>();
		parse(result);
		return result;
	}

	private void processKeywordLine() {
		final RouterMicrodescriptorKeyword keyword = RouterMicrodescriptorKeyword.findKeyword(fieldParser.getCurrentKeyword());
		if(!keyword.equals(RouterMicrodescriptorKeyword.UNKNOWN_KEYWORD)) {
			processKeyword(keyword);
		}
		if(currentDescriptor != null) {
			currentDescriptor.setRawDocumentData(fieldParser.getRawDocument());
		}

	}
	

	private void processKeyword(RouterMicrodescriptorKeyword keyword) {
		fieldParser.verifyExpectedArgumentCount(keyword.getKeyword(), keyword.getArgumentCount());
		switch(keyword) {
		case ONION_KEY:
			processOnionKeyLine();
			break;
			
		case NTOR_ONION_KEY:
			if(currentDescriptor != null) {
				currentDescriptor.setNtorOnionKey(fieldParser.parseNtorPublicKey());
			}
			break;
			
		case FAMILY:
			while(fieldParser.argumentsRemaining() > 0 && currentDescriptor != null) {
				currentDescriptor.addFamilyMember(fieldParser.parseString());
			}
			break;
		
		case P:
			processP();
			break;

		case ID:
			processId();
			break;
	
		case A:
		default:
			break;
		}
	}
	
	private void processOnionKeyLine() {
		if(currentDescriptor != null) {
			finalizeDescriptor(currentDescriptor);
		}
		currentDescriptor = new RouterMicrodescriptorImpl();
		fieldParser.resetRawDocument(RouterMicrodescriptorKeyword.ONION_KEY.getKeyword() + "\n");
		/*
		 * dir-spec: "onion-key" starts every microdescriptor, but since consensus
		 * method 37 the (obsolete, TAP) RSA key object is omitted.  Only parse the
		 * object if one actually follows.
		 */
		if(fieldParser.nextLineIsObject()) {
			currentDescriptor.setOnionKey(fieldParser.parsePublicKey());
		}
	}

	/*
	 * "id" SP "ed25519" SP ed25519-identity NL
	 * "id" SP "rsa1024" SP rsa-identity-digest NL   (ignored)
	 */
	private void processId() {
		if(currentDescriptor == null) {
			return;
		}
		final String keyType = fieldParser.parseString();
		if("ed25519".equals(keyType)) {
			final byte[] key = fieldParser.parseBase64Data();
			if(key.length == 32) {
				currentDescriptor.setEd25519Identity(key);
			} else {
				fieldParser.logWarn("Ignoring 'id ed25519' line with unexpected key length "+ key.length);
			}
		}
	}

	private void finalizeDescriptor(RouterMicrodescriptorImpl descriptor) {
		final TorMessageDigest digest = new TorMessageDigest(true);
		digest.update(descriptor.getRawDocumentData());
		descriptor.setDescriptorDigest(digest.getHexDigest());
		if(!descriptor.isValidDocument()) {
			resultHandler.documentInvalid(descriptor, "Microdescriptor data invalid");
		} else {
			resultHandler.documentParsed(descriptor);
		}
	}

	private void processP() {
		if(currentDescriptor == null) {
			return;
		}
		final String ruleType = fieldParser.parseString();
		if("accept".equals(ruleType)) {
			currentDescriptor.addAcceptPorts(fieldParser.parseString());
		} else if("reject".equals(ruleType)) {
			currentDescriptor.addRejectPorts(fieldParser.parseString());
		} else {
			fieldParser.logWarn("Unexpected P field in microdescriptor: "+ ruleType);
		}
	}
}
