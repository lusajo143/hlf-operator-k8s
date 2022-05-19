/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const adminUserId = 'admin';
const adminUserPasswd = 'adminpw';

/**
 *
 * @param {*} FabricCAServices
 * @param {*} ccp
 */
exports.buildCAClient = (FabricCAServices) => {
	// Create a new CA client for interacting with the CA.
	// const caInfo = ccp.certificateAuthorities[caHostName]; //lookup CA details from config
	// const caTLSCACerts = caInfo.tlsCACerts.pem;
	// const caClient = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

	const caClient = new FabricCAServices('https://192.168.49.2:32169', { trustedRoots: '-----BEGIN CERTIFICATE-----\
	MIICTTCCAfKgAwIBAgIQOgcmrvSRu6rM5NNNgpGG4jAKBggqhkjOPQQDAjBSMRMw\
	EQYDVQQGEwpDYWxpZm9ybmlhMQkwBwYDVQQHEwAxCTAHBgNVBAkTADEUMBIGA1UE\
	ChMLSHlwZXJsZWRnZXIxDzANBgNVBAsTBkZhYnJpYzAeFw0yMjA1MTcwODA2NTVa\
	Fw0zMjA1MTgwODA2NTVaMFIxEzARBgNVBAYTCkNhbGlmb3JuaWExCTAHBgNVBAcT\
	ADEJMAcGA1UECRMAMRQwEgYDVQQKEwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFi\
	cmljMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI0ac3s7tCSIcsTQF5brLHbZc\
	ikKonSw9TBJgGFNoIpJ69hZvIv5JU+fJsadavF/0XyFORljmzmRJpLkpWbmbuqOB\
	qTCBpjAOBgNVHQ8BAf8EBAMCAaYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF\
	BwMBMA8GA1UdEwEB/wQFMAMBAf8wKQYDVR0OBCIEIIfiEf12QWb49dG8d8zhvTkg\
	Xrq+e/wiH0pgH+MkVZcLMDkGA1UdEQQyMDCCCWxvY2FsaG9zdIIHb3JnMS1jYYIO\
	b3JnMS1jYS5mYWJyaWOHBH8AAAGHBMCoMQIwCgYIKoZIzj0EAwIDSQAwRgIhAKfs\
	iw9WxwC4/P6TaNjI3c6vLm8y5IhsAfChw5/wukBmAiEAuSQXKmIK76bsJel3sviM\
	Wex7COQDXaZn/eicvL0B/z4=\
	-----END CERTIFICATE-----', verify: false }, '172-17-0-6.org1-ca.fabric.svc.cluster.local');
	console.log(`Built a CA Client`);

	return caClient;
};

exports.enrollAdmin = async (caClient, wallet, orgMspId) => {
	try {
		// Check to see if we've already enrolled the admin user.
		const identity = await wallet.get(adminUserId);
		if (identity) {
			console.log('An identity for the admin user already exists in the wallet');
			return;
		}

		// Enroll the admin user, and import the new identity into the wallet.
		const enrollment = await caClient.enroll({ enrollmentID: adminUserId, enrollmentSecret: adminUserPasswd });
		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};
		await wallet.put(adminUserId, x509Identity);
		console.log('Successfully enrolled admin user and imported it into the wallet');
	} catch (error) {
		console.error(`Failed to enroll admin user : ${error}`);
	}
};

exports.registerAndEnrollUser = async (caClient, wallet, orgMspId, userId, affiliation) => {
	try {
		// Check to see if we've already enrolled the user
		const userIdentity = await wallet.get(userId);
		if (userIdentity) {
			console.log(`An identity for the user ${userId} already exists in the wallet`);
			return;
		}

		// Must use an admin to register a new user
		const adminIdentity = await wallet.get(adminUserId);
		if (!adminIdentity) {
			console.log('An identity for the admin user does not exist in the wallet');
			console.log('Enroll the admin user before retrying');
			return;
		}

		// build a user object for authenticating with the CA
		const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
		const adminUser = await provider.getUserContext(adminIdentity, adminUserId);

		// Register the user, enroll the user, and import the new identity into the wallet.
		// if affiliation is specified by client, the affiliation value must be configured in CA
		const secret = await caClient.register({
			affiliation: affiliation,
			enrollmentID: userId,
			role: 'client'
		}, adminUser);
		const enrollment = await caClient.enroll({
			enrollmentID: userId,
			enrollmentSecret: secret
		});
		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};
		await wallet.put(userId, x509Identity);
		console.log(`Successfully registered and enrolled user ${userId} and imported it into the wallet`);
	} catch (error) {
		console.error(`Failed to register user : ${error}`);
	}
};
