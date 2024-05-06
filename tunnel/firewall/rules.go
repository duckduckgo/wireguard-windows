/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Known addresses.
var (
	linkLocal = wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	linkLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2}}
	siteLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3}}

	linkLocalRouterMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}
)

func permitTunInterface(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&ifLUID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitWireGuardService(session uintptr, baseObjects *baseObjects, weight uint8) error {
	var conditions [2]wtFwpmFilterCondition0

	//
	// First condition is the exe path of the current process.
	//
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	//
	// Second condition is the SECURITY_DESCRIPTOR of the current process.
	// This prevents other processes hosted in the same exe from matching this filter.
	//
	sd, err := getCurrentProcessSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}

	conditions[1] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
			value: uintptr(unsafe.Pointer(&wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))})),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitBackend(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// Condition is the exe path
	//
	appID, err := getBackendAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for DuckDuckGo Registration Backend (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for DuckDuckGo Registration Backend (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitLoopback(session uintptr, baseObjects *baseObjects, weight uint8) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func enableSplitTunneling(session uintptr, baseObjects *baseObjects, weight uint8, splitTunnelConfig conf.SplitTunnel, tunnelLUID uint64) error {
	calloutKey, _ := windows.GUIDFromString("{565ca03d-428a-42c9-b1a3-c8f081480f4a}")
	_, err := createCallout(session, calloutKey, &baseObjects.splitTunnelProvider, cFWPM_LAYER_ALE_CONNECT_REDIRECT_V4, "Split-tunnel connect redirect callout")
	if err != nil {
		return wrapErr(err)
	}

	udpCalloutKey, _ := windows.GUIDFromString("{46f0a3fd-6404-41e3-b9f6-91b150c7ee8f}")
	_, err = createCallout(session, udpCalloutKey, &baseObjects.splitTunnelProvider, cFWPM_LAYER_ALE_BIND_REDIRECT_V4, "Split-tunnel bind redirect callout")
	if err != nil {
		return wrapErr(err)
	}

	localInterface, err := getLocalInterface(tunnelLUID)
	if err != nil {
		return wrapErr(err)
	}
	providerContextKey, err := createProviderContext(session, &baseObjects.splitTunnelProvider, "Split-tunnel provider context", "Split-tunnel provider context", localInterface)
	if err != nil {
		return wrapErr(err)
	}

	excludedAppPaths := splitTunnelConfig.ExcludedApps
	for _, appPath := range excludedAppPaths {
		err = permitApp(session, baseObjects, weight, appPath)
		if err != nil {
			return wrapErr(err)
		}

		err = createAppFilter(session, baseObjects, cFWPM_LAYER_ALE_CONNECT_REDIRECT_V4, weight, appPath, calloutKey, providerContextKey)
		if err != nil {
			return wrapErr(err)
		}

		err = createAppFilter(session, baseObjects, cFWPM_LAYER_ALE_BIND_REDIRECT_V4, weight, appPath, udpCalloutKey, providerContextKey)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func getLocalInterface(tunnelLUID uint64) (netip.Addr, error) {
	interfaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, iface := range interfaces {
		isValidInterface := iface.OperStatus == winipcfg.IfOperStatusUp && iface.FirstUnicastAddress != nil && iface.FirstGatewayAddress != nil
		isTunnel := uint64(iface.LUID) == tunnelLUID

		if isValidInterface && !isTunnel {
			addr, ok := netip.AddrFromSlice(iface.FirstUnicastAddress.Address.IP())
			if ok {
				return addr, nil
			}
		}
	}

	return netip.Addr{}, errors.New("no valid local interface found")
}

func permitApp(session uintptr, baseObjects *baseObjects, weight uint8, appPath string) error {
	appID, err := getAppId(appPath)
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_BLOB_TYPE,
				value: uintptr(unsafe.Pointer(appID)),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	{
		displayData, err := createWtFwpmDisplayData0("Split-tunnel permit app (out)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	{
		displayData, err := createWtFwpmDisplayData0("Split-tunnel permit app (in)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func createAppFilter(session uintptr, baseObjects *baseObjects, layerKey windows.GUID, weight uint8, appPath string, calloutKey windows.GUID, providerContextKey windows.GUID) error {
	appID, err := getAppId(appPath)
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_BLOB_TYPE,
				value: uintptr(unsafe.Pointer(appID)),
			},
		},
	}

	displayData, err := createWtFwpmDisplayData0("Split-tunnel app filter", appPath)
	if err != nil {
		return wrapErr(err)
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.splitTunnelProvider,
		subLayerKey:         baseObjects.splitTunnelFilters,
		displayData:         *displayData,
		weight:              filterWeight(weight),
		layerKey:            layerKey,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
		action: wtFwpmAction0{
			_type:      cFWP_ACTION_CALLOUT_TERMINATING,
			filterType: calloutKey,
		},
		providerContextKey: providerContextKey,
		flags:              cFWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT,
	}

	filterID := uint64(0)

	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func createProviderContext(session uintptr, providerKey *windows.GUID, name string, description string, localInterface netip.Addr) (windows.GUID, error) {
	displayData, err := createWtFwpmDisplayData0(name, description)
	if err != nil {
		return windows.GUID{}, wrapErr(err)
	}

	providerContextKey, _ := windows.GenerateGUID()
	localInterfaceBytes := localInterface.As4()
	providerContext := &wtFwpmProviderContext0{
		providerContextKey: providerContextKey,
		providerKey:        providerKey,
		displayData:        *displayData,
		providerType:       cFWPM_GENERAL_CONTEXT,
		dataBuffer: &wtFwpByteBlob{
			size: uint32(len(localInterfaceBytes)),
			data: &localInterfaceBytes[0],
		},
	}

	providerContextID := uint64(0)
	err = fwpmProviderContextAdd0(session, providerContext, 0, &providerContextID)
	if err != nil {
		return windows.GUID{}, wrapErr(err)
	}

	return providerContextKey, nil
}

func createCallout(session uintptr, calloutKey windows.GUID, providerKey *windows.GUID, layer windows.GUID, name string) (uint32, error) {
	displayData, err := createWtFwpmDisplayData0(name, "")
	if err != nil {
		return 0, wrapErr(err)
	}
	callout := wtFwpmCallout0{
		calloutKey:      calloutKey,
		displayData:     *displayData,
		flags:           cFWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
		providerKey:     providerKey,
		applicableLayer: layer,
	}

	calloutId := uint32(0)
	err = fwpmCalloutAdd0(session, &callout, 0, &calloutId)
	if err != nil {
		return 0, wrapErr(err)
	}

	return calloutId, nil
}

func permitLocalNetworksIPv4(session uintptr, baseObjects *baseObjects, weight uint8) error {
	// #1 permit outbound traffic to local network
	{
		localNetworks := []networkAddress{
			{"10.0.0.0", "255.0.0.0"},
			{"169.254.0.0", "255.255.0.0"},
			{"172.16.0.0", "255.240.0.0"},
			{"192.168.0.0", "255.255.0.0"},
			{"224.0.0.0", "240.0.0.0"},
			{"255.255.255.255", "255.255.255.255"},
		}

		for _, network := range localNetworks {
			addrAndMask := network.wtFwpV4AddrAndMask()
			condValue := wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&addrAndMask)),
			}
			condition := wtFwpmFilterCondition0{
				fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType:      cFWP_MATCH_EQUAL,
				conditionValue: condValue,
			}
			conditions := []wtFwpmFilterCondition0{condition}

			displayData, err := createWtFwpmDisplayData0(
				fmt.Sprint("Permit outbound IPv4 traffic for local network ", network.cidr()),
				"",
			)
			if err != nil {
				return wrapErr(err)
			}

			filter := wtFwpmFilter0{
				displayData:         *displayData,
				providerKey:         &baseObjects.provider,
				layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
				subLayerKey:         baseObjects.filters,
				weight:              filterWeight(weight),
				numFilterConditions: uint32(len(conditions)),
				filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
				action: wtFwpmAction0{
					_type: cFWP_ACTION_PERMIT,
				},
			}

			filterID := uint64(0)

			err = fwpmFilterAdd0(session, &filter, 0, &filterID)
			if err != nil {
				return wrapErr(err)
			}
		}
	}

	return nil
}

func permitDHCPIPv4(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv6(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv6.
	//
	{
		var conditions [6]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalDHCPMulticast))

		// Repeat the condition type for logical OR.
		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[2].conditionValue.value = uintptr(unsafe.Pointer(&siteLocalDHCPMulticast))

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT16
		conditions[3].conditionValue.value = uintptr(547)

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[4].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[5].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[5].matchType = cFWP_MATCH_EQUAL
		conditions[5].conditionValue._type = cFWP_UINT16
		conditions[5].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv6.
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(547)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_UINT16
		conditions[4].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitNdp(session uintptr, baseObjects *baseObjects, weight uint8) error {
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	type filterDefinition struct {
		displayData *wtFwpmDisplayData0
		conditions  []wtFwpmFilterCondition0
		layer       windows.GUID
	}

	var defs []filterDefinition

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(133)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalRouterMulticast))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 133", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(134)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 134", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(135)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 135", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(136)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 136", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(137)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 137", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	for _, definition := range defs {
		filter.displayData = *definition.displayData
		filter.layerKey = definition.layer
		filter.numFilterConditions = uint32(len(definition.conditions))
		filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&definition.conditions[0]))

		err := fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitHyperV(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// Only applicable on Win8+.
	//
	{
		major, minor, _ := windows.RtlGetNtVersionNumbers()
		win8plus := major > 6 || (major == 6 && minor >= 3)

		if !win8plus {
			return nil
		}
	}

	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_L2_FLAGS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_L2_IS_VM2VM),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Outbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V outbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V inbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_INBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all traffic except what is explicitly permitted by other rules.
func blockAll(session uintptr, baseObjects *baseObjects, weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all DNS traffic except towards specified DNS servers.
func blockDNS(except []netip.Addr, session uintptr, baseObjects *baseObjects, weightAllow, weightDeny uint8) error {
	if weightDeny >= weightAllow {
		return errors.New("The allow weight must be greater than the deny weight")
	}

	denyConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the condition type for logical OR.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightDeny),
		numFilterConditions: uint32(len(denyConditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&denyConditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	allowConditionsV4 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV4 = append(allowConditionsV4, denyConditions...)
	for _, ip := range except {
		if !ip.Is4() {
			continue
		}
		allowConditionsV4 = append(allowConditionsV4, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT32,
				value: uintptr(binary.BigEndian.Uint32(ip.AsSlice())),
			},
		})
	}

	appID, err := getBackendAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	allowAppConditions := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+1)
	allowAppConditions = append(allowAppConditions, denyConditions...)
	allowAppConditions = append(allowAppConditions, wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	})

	storedPointers := make([]*wtFwpByteArray16, 0, len(except))
	allowConditionsV6 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV6 = append(allowConditionsV6, denyConditions...)
	for _, ip := range except {
		if !ip.Is6() {
			continue
		}
		address := wtFwpByteArray16{byteArray16: ip.As16()}
		allowConditionsV6 = append(allowConditionsV6, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_ARRAY16_TYPE,
				value: uintptr(unsafe.Pointer(&address)),
			},
		})
		storedPointers = append(storedPointers, &address)
	}

	filter = wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightAllow),
		numFilterConditions: uint32(len(allowConditionsV4)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV4[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID = uint64(0)

	//
	// #5 Allow IPv4 outbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #6 Allow IPv4 inbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	// Exclude backend
	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowAppConditions[0]))
	filter.numFilterConditions = uint32(len(allowAppConditions))
	if len(allowAppConditions) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow outbound DNS on Backend (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}
	if len(allowAppConditions) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow inbound DNS on Backend (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV6[0]))
	filter.numFilterConditions = uint32(len(allowConditionsV6))

	//
	// #7 Allow IPv6 outbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #8 Allow IPv6 inbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(storedPointers)

	return nil
}
