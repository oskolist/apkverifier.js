/**
 * Minimal JAR manifest / signature-file (.SF) parser.
 *
 * Manifest entries are line-oriented (RFC 822-ish): sections separated by a blank
 * line, `Key: Value` attributes, and a single leading-space continuation line
 * folds into the previous attribute's value. We only need attribute *lookup*
 * (for the per-entry / per-section digests), so we parse to text and decode
 * base64 digests on demand.
 */

export interface ManifestSection {
	/** Entry name, or `null` for the manifest main section / SF main section. */
	name: string | null;
	/** Attribute name -> raw value (string). */
	attrs: Map<string, string>;
}

export interface ManifestFile {
	/** The first (main) section. */
	main: ManifestSection;
	/** Named per-entry sections, keyed by their `Name` attribute. */
	entries: Map<string, ManifestSection>;
}

/** Parse the (uncompressed) bytes of a manifest or .SF file. */
export function parseManifest(bytes: Uint8Array): ManifestFile {
	const text = decodeText(bytes);
	const lines = text.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
	const sections: ManifestSection[] = [];
	let cur: ManifestSection | null = null;
	let prevKey: string | null = null;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (line.length === 0) {
			// blank line -> section boundary
			if (cur) sections.push(cur);
			cur = null;
			prevKey = null;
			continue;
		}
		if (line[0] === " " || line[0] === "\t") {
			// continuation of the previous attribute's value
			if (prevKey !== null && cur) {
				cur.attrs.set(prevKey, cur.attrs.get(prevKey)! + line.slice(1));
			}
			continue;
		}
		const colon = line.indexOf(":");
		if (colon < 0) {
			// not a valid attribute line; skip
			prevKey = null;
			continue;
		}
		const key = line.slice(0, colon).trim();
		const val = line.slice(colon + 1).trim();
		if (!cur) cur = { name: null, attrs: new Map() };
		if (key.toLowerCase() === "name") {
			cur.name = val;
		}
		cur.attrs.set(key, val);
		prevKey = key;
	}
	if (cur) sections.push(cur); // file may not end with a trailing blank line

	const main = sections[0] ?? { name: null, attrs: new Map() };
	const entries = new Map<string, ManifestSection>();
	for (let i = 1; i < sections.length; i++) {
		const s = sections[i];
		if (s.name) entries.set(s.name, s);
	}
	return { main, entries };
}

/** Decode UTF-8 bytes to a string (manifest files are ASCII/UTF-8). */
function decodeText(bytes: Uint8Array): string {
	return new TextDecoder("utf-8").decode(bytes);
}

/** Decode a base64 string to bytes (works in Node >= 16 and browsers via global `atob`). */
export function b64toBytes(b64: string): Uint8Array {
	const binary = atob(b64.trim());
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}
