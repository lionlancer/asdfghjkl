package com.chariotsolutions.nfc.plugin;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.nio.charset.Charset;

// using wildcard imports so we can support Cordova 3.x
import org.apache.cordova.*; // Cordova 3.x

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.NfcA;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Parcelable;
import android.util.Log;


public class NfcPlugin extends CordovaPlugin implements NfcAdapter.OnNdefPushCompleteCallback {
    private static final String REGISTER_MIME_TYPE = "registerMimeType";
    private static final String REMOVE_MIME_TYPE = "removeMimeType";
    private static final String REGISTER_NDEF = "registerNdef";
    private static final String REMOVE_NDEF = "removeNdef";
    private static final String REGISTER_NDEF_FORMATABLE = "registerNdefFormatable";
    private static final String REGISTER_DEFAULT_TAG = "registerTag";
    private static final String REMOVE_DEFAULT_TAG = "removeTag";
    private static final String WRITE_TAG = "writeTag";
    private static final String MAKE_READ_ONLY = "makeReadOnly";
    private static final String ERASE_TAG = "eraseTag";
    private static final String SHARE_TAG = "shareTag";
    private static final String UNSHARE_TAG = "unshareTag";
    private static final String HANDOVER = "handover"; // Android Beam
    private static final String STOP_HANDOVER = "stopHandover";
    private static final String ENABLED = "enabled";
    private static final String INIT = "init";
    private static final String SHOW_SETTINGS = "showSettings";

    private static final String NDEF = "ndef";
    private static final String NDEF_MIME = "ndef-mime";
    private static final String NDEF_FORMATABLE = "ndef-formatable";
    private static final String TAG_DEFAULT = "tag";

    private static final String STATUS_NFC_OK = "NFC_OK";
    private static final String STATUS_NO_NFC = "NO_NFC";
    private static final String STATUS_NFC_DISABLED = "NFC_DISABLED";
    private static final String STATUS_NDEF_PUSH_DISABLED = "NDEF_PUSH_DISABLED";

    private static final String TAG = "NfcPlugin";
    private final List<IntentFilter> intentFilters = new ArrayList<IntentFilter>();
    private final ArrayList<String[]> techLists = new ArrayList<String[]>();

    private NdefMessage p2pMessage = null;
    private PendingIntent pendingIntent = null;

    private Intent savedIntent = null;

    private CallbackContext shareTagCallback;
    private CallbackContext handoverCallback;

	// Password has to be 4 characters
	// Password Acknowledge has to be 2 characters
	private byte[] pwd      = "l10n".getBytes();
	private	byte[] pack     = "sR".getBytes();
	
	private String act = ""; 
	private boolean isProtected = false;
	private NfcA gNfcA;
	private Tag gTag;
	
    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

        Log.d(TAG, "execute " + action);

        // showSettings can be called if NFC is disabled
        // might want to skip this if NO_NFC
        if (action.equalsIgnoreCase(SHOW_SETTINGS)) {
            showSettings(callbackContext);
            return true;
        }

        if (!getNfcStatus().equals(STATUS_NFC_OK)) {
            callbackContext.error(getNfcStatus());
            return true; // short circuit
        }

        createPendingIntent();

        if (action.equalsIgnoreCase(REGISTER_MIME_TYPE)) {
            registerMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_MIME_TYPE)) {
          removeMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF)) {
          registerNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_NDEF)) {
          removeNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF_FORMATABLE)) {
            registerNdefFormatable(callbackContext);

        }  else if (action.equals(REGISTER_DEFAULT_TAG)) {
          registerDefaultTag(callbackContext);

        }  else if (action.equals(REMOVE_DEFAULT_TAG)) {
          removeDefaultTag(callbackContext);

        } else if (action.equalsIgnoreCase(WRITE_TAG)) {
            writeTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(MAKE_READ_ONLY)) {
            makeReadOnly(callbackContext);

        } else if (action.equalsIgnoreCase(ERASE_TAG)) {
            eraseTag(callbackContext);

        } else if (action.equalsIgnoreCase(SHARE_TAG)) {
            shareTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(UNSHARE_TAG)) {
            unshareTag(callbackContext);

        } else if (action.equalsIgnoreCase(HANDOVER)) {
            handover(data, callbackContext);

        } else if (action.equalsIgnoreCase(STOP_HANDOVER)) {
            stopHandover(callbackContext);

        } else if (action.equalsIgnoreCase(INIT)) {
            init(callbackContext);

        } else if (action.equalsIgnoreCase(ENABLED)) {
            // status is checked before every call
            // if code made it here, NFC is enabled
            callbackContext.success(STATUS_NFC_OK);

        } else {
            // invalid action
            return false;
        }

        return true;
    }

    private String getNfcStatus() {
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
        if (nfcAdapter == null) {
            return STATUS_NO_NFC;
        } else if (!nfcAdapter.isEnabled()) {
            return STATUS_NFC_DISABLED;
        } else {
            return STATUS_NFC_OK;
        }
    }

    private void registerDefaultTag(CallbackContext callbackContext) {
      addTagFilter();
      callbackContext.success();
  }

    private void removeDefaultTag(CallbackContext callbackContext) {
      removeTagFilter();
      callbackContext.success();
  }

    private void registerNdefFormatable(CallbackContext callbackContext) {
        addTechList(new String[]{NdefFormatable.class.getName()});
        callbackContext.success();
    }

    private void registerNdef(CallbackContext callbackContext) {
      addTechList(new String[]{Ndef.class.getName()});
      callbackContext.success();
  }

    private void removeNdef(CallbackContext callbackContext) {
      removeTechList(new String[]{Ndef.class.getName()});
      callbackContext.success();
  }

    private void unshareTag(CallbackContext callbackContext) {
        p2pMessage = null;
        stopNdefPush();
        shareTagCallback = null;
        callbackContext.success();
    }

    private void init(CallbackContext callbackContext) {
        Log.d(TAG, "Enabling plugin " + getIntent());

        startNfc();
        if (!recycledIntent()) {
            parseMessage();
        }
		
		Log.d(TAG, "Returning success... ");
        callbackContext.success();
    }

    private void removeMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = "";
        try {
            mimeType = data.getString(0);
            /*boolean removed =*/ removeIntentFilter(mimeType);
            callbackContext.success();
        } catch (MalformedMimeTypeException e) {
            callbackContext.error("Invalid MIME Type " + mimeType);
        }
    }

    private void registerMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = "";
        try {
            mimeType = data.getString(0);
            intentFilters.add(createIntentFilter(mimeType));
            callbackContext.success();
        } catch (MalformedMimeTypeException e) {
            callbackContext.error("Invalid MIME Type " + mimeType);
        }
    }

    // Cheating and writing an empty record. We may actually be able to erase some tag types.
    private void eraseTag(CallbackContext callbackContext) throws JSONException {
        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = {
            new NdefRecord(NdefRecord.TNF_EMPTY, new byte[0], new byte[0], new byte[0])
        };
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        if (getIntent() == null) {  // TODO remove this and handle LostTag
            callbackContext.error("Failed to write tag, received null intent");
        }
		
		Log.d(TAG, "DATA: " + data.toString());
		
        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeNdefMessage(final NdefMessage message, final Tag tag, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                
				boolean isWritable = false;
				boolean isReadOnly = false;
				int maxSize = 0;
				
				boolean proceed = false;
				
				Ndef ndef;
				
				Log.d(TAG, "WRITING DATA...");
				
				try {
					// use ndef to find out if card is writable or not
                    ndef = Ndef.get(tag);
                    if (ndef != null) {
                        ndef.connect();

						isWritable = ndef.isWritable();	
						
                        if (isWritable) {
                            maxSize = message.toByteArray().length;
                            if (ndef.getMaxSize() < maxSize) {
                                callbackContext.error("Tag capacity is " + ndef.getMaxSize() +
                                        " bytes, message is " + maxSize + " bytes.");
                            } else {
                                //ndef.writeNdefMessage(message);
                                //callbackContext.success();
                            }
                        } else {
                            callbackContext.error("Tag is read only");
                        }
                        
						ndef.close();
						
                    } else {
                        NdefFormatable formatable = NdefFormatable.get(tag);
                        if (formatable != null) {
                            formatable.connect();
                            formatable.format(message);
                            callbackContext.success();
                            formatable.close();
                        } else {
                            callbackContext.error("Tag doesn't support NDEF");
                        }
                    }
				
				} catch (FormatException e) {
                    callbackContext.error(e.getMessage());
					
                } catch (TagLostException e) {
                    callbackContext.error(e.getMessage());
                } catch (IOException e) {
                    callbackContext.error(e.getMessage());
                }
				
				
				byte[] response;
				boolean authError = true;
				
				NfcA nfca = NfcA.get(tag);
				
				try{
					nfca.connect();
				} catch (TagLostException e) {
					callbackContext.error("Connect TagLostException Error: " + e.getMessage());
				} catch (IOException e) {
					callbackContext.error("Connect IOException Error: " + e.getMessage());
				}	
				
				// authenticate
				nfca = authenticate(nfca);
				
				// open access
				//nfca = enableProtection(nfca, false);
				
				/*
				try{
					nfca.close();
				}catch(Exception e){
					Log.d(TAG, "NFCA CLOSE Error: " + e.getMessage());
				}
				
				try{
					ndef = Ndef.get(tag);
					try{
						ndef.connect();
					}catch(Exception e){
						Log.d(TAG, "Writing NDEF MEssage connect Error: " + e.getMessage());
					}
					// write message via ndef
					try{
						
						ndef.writeNdefMessage(message);
					}catch(Exception e){
						Log.d(TAG, "Writing NDEF MEssage started Error: " + e.getMessage());
						String msg = new String(message.getRecords()[0].getPayload());
						Log.d(TAG, "Payload: " + msg);
					}
					
					try{
						ndef.close();
					}catch(Exception e){
						Log.d(TAG, "Writing NDEF MEssage closing Error: " + e.getMessage());
					}
				}catch(Exception e){
					Log.d(TAG, "writeNdefMessage Error: " + e.getMessage());
				}
				
				try{
					TimeUnit.SECONDS.sleep(2);
				}catch(Exception e){
					Log.d(TAG, "Sleep Error: " + e.getMessage());
				}
				
				
				try{	
					nfca.connect();
				} catch (TagLostException e) {
					callbackContext.error("Connect TagLostException Error: " + e.getMessage());
				} catch (IOException e) {
					callbackContext.error("Connect IOException Error: " + e.getMessage());
				}	
				
				Log.d(TAG, "Reconnected...");
				
				// re-auth
				nfca = authenticate(nfca);
				
				Log.d(TAG, "Authenticated...");
				*/
				// close access
				nfca = enableProtection(nfca, true);
				
				Log.d(TAG, "EnabledProtection");
				
				try{
					// Send PACK and PWD
					// set PACK:
					nfca.transceive(new byte[] {
							(byte)0xA2,
							(byte)0x86,
							pack[0], pack[1], 0, 0  // Write PACK into first 2 Bytes and 0 in RFUI bytes
					});
					// set PWD:
					nfca.transceive(new byte[] {
							(byte)0xA2,
							(byte)0x85,
							pwd[0], pwd[1], pwd[2], pwd[3] // Write all 4 PWD bytes into Page 43
					});
					
					nfca.transceive(new byte[] {
							(byte)0xA2, // WRITE
							(byte)3,    // block address
							//(byte)0xE1, (byte)0x10, (byte)0x12, (byte)0x00 NTAG213
							(byte)0xE1, (byte)0x10, (byte)0x3E, (byte)0x00 // NTAG215
					});
				}catch(Exception e){
					Log.d(TAG, "Error in Send PACK and PWD: " + e.getMessage());
				}
				
				Log.d(TAG, "Set PWD and PACK");
				
				/*
				try {
					nfca.close();
					Log.d(TAG, "NFCA Closed");
				} catch (IOException e) {
					Log.d(TAG, "IOException Error: " + e.getMessage());
					//e.printStackTrace();
				}
				*/
				
				
				byte[] ndefMessage = message.toByteArray();
				
				// wrap into TLV structure
				byte[] tlvEncodedData = null;

				tlvEncodedData = new byte[ndefMessage.length + 3];
				tlvEncodedData[0] = (byte)0x03;  // NDEF TLV tag
				tlvEncodedData[1] = (byte)(ndefMessage.length & 0x0FF);  // NDEF TLV length (1 byte)
				System.arraycopy(ndefMessage, 0, tlvEncodedData, 2, ndefMessage.length);
				tlvEncodedData[2 + ndefMessage.length] = (byte)0xFE;  // Terminator TLV tag

				// fill up with zeros to block boundary:
				tlvEncodedData = Arrays.copyOf(tlvEncodedData, (tlvEncodedData.length / 4 + 1) * 4);
				for (int i = 0; i < tlvEncodedData.length; i += 4) {
					byte[] command = new byte[] {
							(byte)0xA2, // WRITE
							(byte)((4 + i / 4) & 0x0FF), // block address
							0, 0, 0, 0
					};
					System.arraycopy(tlvEncodedData, i, command, 2, 4);
					try {
						response = nfca.transceive(command);
						Log.d(TAG, "Response got!: " + Arrays.toString(response));
						//Log.d(TAG, response);
						
					} catch (IOException e) {
						Log.d(TAG, "Error:" + e.getMessage());
						//e.printStackTrace();
					}
				}
				
				
				try {
					nfca.close();
					Log.d(TAG, "NFCA Closed");
				} catch (IOException e) {
					Log.d(TAG, "IOException Error: " + e.getMessage());
					e.printStackTrace();
				}
				
				
				callbackContext.success();
				
            }
        });
    }

	private NfcA authenticate(NfcA nfca){
		
		try {
			byte[] response = nfca.transceive(new byte[]{
					(byte) 0x1B, // PWD_AUTH
					pwd[0], pwd[1], pwd[2], pwd[3]
			});
			
			// Check if PACK is matching expected PACK
			// This is a (not that) secure method to check if tag is genuine
			if ((response != null) && (response.length >= 2)) {
				//authError = false;
				
				byte[] packResponse = Arrays.copyOf(response, 2);
				if (!(pack[0] == packResponse[0] && pack[1] == packResponse[1])) {
					Log.d(TAG, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString());
					//Toast.makeText(ctx, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString(), Toast.LENGTH_LONG).show();
				}else{
					
				}
			}
		}catch(Exception e){
			Log.d(TAG, "Tranceive Exception Error: " + e.getMessage());
			//e.printStackTrace();
		}
		
		return nfca;
	}
	
	private NfcA enableProtection(NfcA nfca, boolean protect){
		
		byte[] response;
		
		// open access
		try{
			// Get Page 2Ah
			response = nfca.transceive(new byte[] {
					(byte) 0x30, // READ
					//(byte) 0x2A  // page address
					(byte) 0x84  // page address
			});
			// configure tag as write-protected with unlimited authentication tries
			if ((response != null) && (response.length >= 16)) {    // read always returns 4 pages
				//boolean prot = false;                               // false = PWD_AUTH for write only, true = PWD_AUTH for read and write
				//if(saveType == "Protected") prot = false;
				//prot = true;
											
				int authlim = 0;                                    // 0 = unlimited tries
				nfca.transceive(new byte[] {
						(byte) 0xA2, // WRITE
						(byte) 0x84, // page address
						(byte) ((response[0] & 0x078) | (protect ? 0x080 : 0x000) | (authlim & 0x007)),    	// set ACCESS byte according to our settings
						0, 0, 0                                                                         	// fill rest as zeros as stated in datasheet (RFUI must be set as 0b)
				});
			}
		}catch(Exception e){
			Log.d(TAG, "Error in Get Page 2Ah: " + e.getMessage());
		}
		
		try{
			// Get page 29h
			response = nfca.transceive(new byte[] {
					(byte) 0x30, // READ
					(byte) 0x83  // page address
			});
			// Configure tag to protect entire storage (page 0 and above)
			if ((response != null) && (response.length >= 16)) {  // read always returns 4 pages
				int auth0 = 0;                                    // first page to be protected
				nfca.transceive(new byte[] {
						(byte) 0xA2, // WRITE
						(byte) 0x83, // page address
						response[0], 0, response[2],              // Keep old mirror values and write 0 in RFUI byte as stated in datasheet
						(byte) (auth0 & 0x0ff)
				});
			}
		}catch(Exception e){
			Log.d(TAG, "Error in Get Page 29h: " + e.getMessage());
		}
		
		return nfca;
	}
	
    private void makeReadOnly(final CallbackContext callbackContext) throws JSONException {

        if (getIntent() == null) { // Lost Tag
            callbackContext.error("Failed to make tag read only, received null intent");
            return;
        }

        final Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) {
            callbackContext.error("Failed to make tag read only, tag is null");
            return;
        }

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                boolean success = false;
                String message = "Could not make tag read only";

                Ndef ndef = Ndef.get(tag);

                try {
                    if (ndef != null) {

                        ndef.connect();

                        if (!ndef.isWritable()) {
                            message = "Tag is not writable";
                        } else if (ndef.canMakeReadOnly()) {
                            success = ndef.makeReadOnly();
                        } else {
                            message = "Tag can not be made read only";
                        }

                    } else {
                        message = "Tag is not NDEF";
                    }

                } catch (IOException e) {
                    Log.e(TAG, "Failed to make tag read only", e);
                    if (e.getMessage() != null) {
                        message = e.getMessage();
                    } else {
                        message = e.toString();
                    }
                }

                if (success) {
                    callbackContext.success();
                } else {
                    callbackContext.error(message);
                }
            }
        });
    }

    private void shareTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        this.p2pMessage = new NdefMessage(records);

        startNdefPush(callbackContext);
    }

    // setBeamPushUris
    // Every Uri you provide must have either scheme 'file' or scheme 'content'.
    // Note that this takes priority over setNdefPush
    //
    // See http://developer.android.com/reference/android/nfc/NfcAdapter.html#setBeamPushUris(android.net.Uri[],%20android.app.Activity)
    private void handover(JSONArray data, CallbackContext callbackContext) throws JSONException {

        Uri[] uri = new Uri[data.length()];

        for (int i = 0; i < data.length(); i++) {
            uri[i] = Uri.parse(data.getString(i));
        }

        startNdefBeam(callbackContext, uri);
    }

    private void stopHandover(CallbackContext callbackContext) throws JSONException {
        stopNdefBeam();
        handoverCallback = null;
        callbackContext.success();
    }

    private void showSettings(CallbackContext callbackContext) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.JELLY_BEAN) {
            Intent intent = new Intent(android.provider.Settings.ACTION_NFC_SETTINGS);
            getActivity().startActivity(intent);
        } else {
            Intent intent = new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS);
            getActivity().startActivity(intent);
        }
        callbackContext.success();
    }

    private void createPendingIntent() {
        if (pendingIntent == null) {
            Activity activity = getActivity();
            Intent intent = new Intent(activity, activity.getClass());
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            pendingIntent = PendingIntent.getActivity(activity, 0, intent, 0);
        }
    }

    private void addTechList(String[] list) {
      this.addTechFilter();
      this.addToTechList(list);
    }

    private void removeTechList(String[] list) {
      this.removeTechFilter();
      this.removeFromTechList(list);
    }

    private void addTechFilter() {
      intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED));
    }

    private boolean removeTechFilter() {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intentFilter.getAction(0))) {
          iter.remove();
          removed = true;
        }
      }
      return removed;
    }

    private void addTagFilter() {
      intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED));
  }

    private boolean removeTagFilter() {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intentFilter.getAction(0))) {
          iter.remove();
          removed = true;
        }
      }
      return removed;
  }

    private void startNfc() {
        createPendingIntent(); // onResume can call startNfc before execute

        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null && !getActivity().isFinishing()) {
                    try {
                        nfcAdapter.enableForegroundDispatch(getActivity(), getPendingIntent(), getIntentFilters(), getTechLists());

                        if (p2pMessage != null) {
                            nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                        }
                    } catch (IllegalStateException e) {
                        // issue 110 - user exits app with home button while nfc is initializing
                        Log.w(TAG, "Illegal State Exception starting NFC. Assuming application is terminating.");
                    }

                }
            }
        });
    }

    private void stopNfc() {
        Log.d(TAG, "stopNfc");
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    try {
                        nfcAdapter.disableForegroundDispatch(getActivity());
                    } catch (IllegalStateException e) {
                        // issue 125 - user exits app with back button while nfc
                        Log.w(TAG, "Illegal State Exception stopping NFC. Assuming application is terminating.");
                    }
                }
            }
        });
    }

    private void startNdefBeam(final CallbackContext callbackContext, final Uri[] uris) {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter == null) {
                    callbackContext.error(STATUS_NO_NFC);
                } else if (!nfcAdapter.isNdefPushEnabled()) {
                    callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
                } else {
                    nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());
                    try {
                        nfcAdapter.setBeamPushUris(uris, getActivity());

                        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                        result.setKeepCallback(true);
                        handoverCallback = callbackContext;
                        callbackContext.sendPluginResult(result);

                    } catch (IllegalArgumentException e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            }
        });
    }

    private void startNdefPush(final CallbackContext callbackContext) {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter == null) {
                    callbackContext.error(STATUS_NO_NFC);
                } else if (!nfcAdapter.isNdefPushEnabled()) {
                    callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
                } else {
                    nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                    nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());

                    PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                    result.setKeepCallback(true);
                    shareTagCallback = callbackContext;
                    callbackContext.sendPluginResult(result);
                }
            }
        });
    }

    private void stopNdefPush() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    nfcAdapter.setNdefPushMessage(null, getActivity());
                }

            }
        });
    }

    private void stopNdefBeam() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    nfcAdapter.setBeamPushUris(null, getActivity());
                }

            }
        });
    }

    private void addToTechList(String[] techs) {
      techLists.add(techs);
  }

    private void removeFromTechList(String[] techs) {
      techLists.remove(techs);
  }

    private boolean removeIntentFilter(String mimeType) throws MalformedMimeTypeException {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        String mt = intentFilter.getDataType(0);
        if (mimeType.equals(mt)) {
          iter.remove();
          removed = true;
        }
      }
      return removed;
    }

    private IntentFilter createIntentFilter(String mimeType) throws MalformedMimeTypeException {
        IntentFilter intentFilter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        intentFilter.addDataType(mimeType);
        return intentFilter;
    }

    private PendingIntent getPendingIntent() {
        return pendingIntent;
    }

    private IntentFilter[] getIntentFilters() {
        return intentFilters.toArray(new IntentFilter[intentFilters.size()]);
    }

    private String[][] getTechLists() {
        //noinspection ToArrayCallWithZeroLengthArrayArgument
        return techLists.toArray(new String[0][0]);
    }

    void parseMessage() {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                Log.d(TAG, "READING....");
                
				
				Log.d(TAG, "parseMessage " + getIntent());
                Intent intent = getIntent();
                String action = intent.getAction();
                Log.d(TAG, "action " + action);
                if (action == null) {
                    return;
                }

                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                Parcelable[] messages = intent.getParcelableArrayExtra((NfcAdapter.EXTRA_NDEF_MESSAGES));

				boolean isAuthOK = false;
				
				NfcA nfca = null;
				byte[] response;
				
				Ndef ndef = null;
				
				boolean readProtected = false;
				
				try{
					nfca = NfcA.get(tag);
					nfca.connect();
					
					response = null;
					
					try{
						// find out if tag is password protected
						response = nfca.transceive(new byte[] {
							(byte) 0x30, // READ
							//(byte) 0x83  // page address
							(byte) (131 & 0x0FF)  // page address
						});
					}catch(Exception e){
						readProtected = true;
						Log.d(TAG, "find out if tag is password protected Error: " + e.getMessage());
					}
					
					// Authenticate with the tag first
					// only if the Auth0 byte is not 0xFF,
					// which is the default value meaning unprotected
					if((response != null && (response[3] != (byte)0xFF)) || readProtected) {
						
						isProtected = true;
						gNfcA = nfca;
						gTag = tag;
						
						nfca = authenticate(nfca);
						// open access
						nfca = enableProtection(nfca, false);
						
						
					}else {
						//isAuthOK = true;
						isProtected = false;
					}
					
					nfca.close();
					
				}catch(Exception e){
					Log.d(TAG, "Unlocking error: " + e.getMessage());
				}
				
				
                if (action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)) {
                    ndef = Ndef.get(tag);
                    fireNdefEvent(NDEF_MIME, ndef, messages);

                } else if (action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {
                    for (String tagTech : tag.getTechList()) {
                        Log.d(TAG, tagTech);
                        if (tagTech.equals(NdefFormatable.class.getName())) {
                            fireNdefFormatableEvent(tag);
                        } else if (tagTech.equals(Ndef.class.getName())) { //
                            ndef = Ndef.get(tag);
                            fireNdefEvent(NDEF, ndef, messages);
                        }
                    }
                }

                if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)) {
                    fireTagEvent(tag);
                }

                setIntent(new Intent());
				
				/*
				Log.d(TAG, "parseMessage " + getIntent());
                Intent intent = getIntent();
                String action = intent.getAction();
                Log.d(TAG, "action " + action);
                if (action == null) {
                    return;
                }

                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                Parcelable[] messages = intent.getParcelableArrayExtra((NfcAdapter.EXTRA_NDEF_MESSAGES));

                if (action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)) {
                    Ndef ndef = Ndef.get(tag);
                    fireNdefEvent(NDEF_MIME, ndef, messages);

                } else if (action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {
                    for (String tagTech : tag.getTechList()) {
                        Log.d(TAG, tagTech);
                        if (tagTech.equals(NdefFormatable.class.getName())) {
                            fireNdefFormatableEvent(tag);
                        } else if (tagTech.equals(Ndef.class.getName())) { //
                            Ndef ndef = Ndef.get(tag);
                            fireNdefEvent(NDEF, ndef, messages);
                        }
                    }
                }

                if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)) {
                    fireTagEvent(tag);
                }

                setIntent(new Intent());
				*/
            }
        });
    }
	
    private void fireNdefEvent(String type, Ndef ndef, Parcelable[] messages) {

		//if(isProtected) lockTag();
		
	
        JSONObject jsonObject = buildNdefJSON(ndef, messages);
        String tag = jsonObject.toString();

        String command = MessageFormat.format(javaScriptEventTemplate, type, tag);
        Log.v(TAG, command);
        this.webView.sendJavascript(command);

    }

    private void fireNdefFormatableEvent (Tag tag) {
		
		//if(isProtected) lockTag();
	
        String command = MessageFormat.format(javaScriptEventTemplate, NDEF_FORMATABLE, Util.tagToJSON(tag));
        Log.v(TAG, command);
        this.webView.sendJavascript(command);
    }

    private void fireTagEvent (Tag tag) {

		//if(isProtected) lockTag();
	
        String command = MessageFormat.format(javaScriptEventTemplate, TAG_DEFAULT, Util.tagToJSON(tag));
        Log.v(TAG, command);
        this.webView.sendJavascript(command);
    }

	private void lockTag(){
		byte[] response;
		
		try{
			NfcA nfca = NfcA.get(gTag);
			// close access
			nfca.connect(); 
			
			try{
				response = nfca.transceive(new byte[]{
						(byte) 0x1B, // PWD_AUTH
						pwd[0], pwd[1], pwd[2], pwd[3]
				});
				
				// Check if PACK is matching expected PACK
				// This is a (not that) secure method to check if tag is genuine
				if ((response != null) && (response.length >= 2)) {
					//authError = false;
					
					byte[] packResponse = Arrays.copyOf(response, 2);
					if (!(pack[0] == packResponse[0] && pack[1] == packResponse[1])) {
						Log.d(TAG, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString());
						//Toast.makeText(ctx, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString(), Toast.LENGTH_LONG).show();
					}else{
						Log.d(TAG, "Tag authenticated.");
					}
				}else{
					if(response == null){
						Log.d(TAG, "NULL RESPONSE");
					}
					if(response.length <= 1){
						Log.d(TAG, "RESPONSE LENGTH <= 1");
					}
					Log.d(TAG, "NOT AUTHENTICATEDDDDDD");
					Log.d(TAG, "Response: " + response.toString());
				}
			}catch(Exception e){
				Log.d(TAG, "Close AUTH Error: " + e.getMessage());
			}
			
			
			
			// Get Page 2Ah
			response = nfca.transceive(new byte[] {
					(byte) 0x30, // READ
					//(byte) 0x2A  // page address
					(byte) 0x84  // page address
			});
			// configure tag as write-protected with unlimited authentication tries
			if ((response != null) && (response.length >= 16)) {    // read always returns 4 pages
				boolean prot = true;                               // false = PWD_AUTH for write only, true = PWD_AUTH for read and write
				int authlim = 0;                                    // 0 = unlimited tries
				nfca.transceive(new byte[] {
						(byte) 0xA2, // WRITE
						//(byte) 0x2A, // page address
						(byte) 0x84, // page address
						(byte) ((response[0] & 0x078) | (prot ? 0x080 : 0x000) | (authlim & 0x007)),    // set ACCESS byte according to our settings
						0, 0, 0                                                                         // fill rest as zeros as stated in datasheet (RFUI must be set as 0b)
				});
			}
			nfca.close(); 
			
			Log.d(TAG, "closed Acess");
		}catch(Exception e){
			Log.d(TAG, "Close Acess Exception Error: " + e.getMessage());
			//e.printStackTrace();
		}
	}
	
    JSONObject buildNdefJSON(Ndef ndef, Parcelable[] messages) {

        JSONObject json = Util.ndefToJSON(ndef);

        // ndef is null for peer-to-peer
        // ndef and messages are null for ndef format-able
        if (ndef == null && messages != null) {

            try {

                if (messages.length > 0) {
                    NdefMessage message = (NdefMessage) messages[0];
                    json.put("ndefMessage", Util.messageToJSON(message));
                    // guessing type, would prefer a more definitive way to determine type
                    json.put("type", "NDEF Push Protocol");
                }

                if (messages.length > 1) {
                    Log.wtf(TAG, "Expected one ndefMessage but found " + messages.length);
                }

            } catch (JSONException e) {
                // shouldn't happen
                Log.e(Util.TAG, "Failed to convert ndefMessage into json", e);
            }
        }
        return json;
    }

    private boolean recycledIntent() { // TODO this is a kludge, find real solution

        int flags = getIntent().getFlags();
        if ((flags & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) == Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) {
            Log.i(TAG, "Launched from history, killing recycled intent");
            setIntent(new Intent());
            return true;
        }
        return false;
    }

    @Override
    public void onPause(boolean multitasking) {
        Log.d(TAG, "onPause " + getIntent());
        super.onPause(multitasking);
        if (multitasking) {
            // nfc can't run in background
            stopNfc();
        }
    }

    @Override
    public void onResume(boolean multitasking) {
        Log.d(TAG, "onResume " + getIntent());
        super.onResume(multitasking);
        startNfc();
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.d(TAG, "onNewIntent " + intent);
        super.onNewIntent(intent);
        setIntent(intent);
        savedIntent = intent;
        parseMessage();
		Log.d(TAG, "onNewIntent returned");
    }

    private Activity getActivity() {
        return this.cordova.getActivity();
    }

    private Intent getIntent() {
        return getActivity().getIntent();
    }

    private void setIntent(Intent intent) {
        getActivity().setIntent(intent);
    }

    String javaScriptEventTemplate =
        "var e = document.createEvent(''Events'');\n" +
        "e.initEvent(''{0}'');\n" +
        "e.tag = {1};\n" +
        "document.dispatchEvent(e);";

    @Override
    public void onNdefPushComplete(NfcEvent event) {

        // handover (beam) take precedence over share tag (ndef push)
        if (handoverCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Beamed Message to Peer");
            result.setKeepCallback(true);
            handoverCallback.sendPluginResult(result);
        } else if (shareTagCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Shared Message with Peer");
            result.setKeepCallback(true);
            shareTagCallback.sendPluginResult(result);
        }

    }
}
