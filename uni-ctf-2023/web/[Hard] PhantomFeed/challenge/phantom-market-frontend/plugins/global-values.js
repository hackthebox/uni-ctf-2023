export default ({ app }, inject) => {
	const globalValues = {
		authServer: window.location.protocol + "//" + window.location.host + "/phantomfeed",
		resourceServer: window.location.protocol + "//" + window.location.host + "/backend",
		marketServer: window.location.protocol + "//" + window.location.host,
		clientId: "phantom-market",
	};

	inject("globalValues", globalValues);
};
