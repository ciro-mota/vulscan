description = [[
Vulscan enhances nmap to a vulnerability scanner by matching service versions
against offline vulnerability databases.

Usage:
  nmap -sV --script=vulscan/vulscan.nse <target>

Arguments:
  --script-args vulscandb=<db>           Use single database
  --script-args vulscanoutput=<format>   Output format (details/listid/listlink/listtitle)
  --script-args vulscanshowall=1         Show all matches
  --script-args vulscanversiondetection=0 Disable version matching
  --script-args vulscaninteractive=1     Interactive mode
]]

author = "Marc Ruef, marc.ruef-at-computec.ch, https://www.computec.ch/mruef/"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

local stdnse = require("stdnse")
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit

portrule = function(host, port)
	if port.version.product ~= nil and port.version.product ~= "" then
		return true
	else
		stdnse.print_debug(1, "vulscan: No version detection data available. Analysis not possible.")
	end
end

action = function(host, port)
	local prod = port.version.product	-- product name
	local ver = port.version.version	-- product version
	local struct = "[{id}] {title}\n"	-- default report structure
	local db = {}				-- vulnerability database
	local db_link = ""			-- custom link for vulnerability databases
	local vul = {}				-- details for the vulnerability
	local v_count = 0			-- counter for the vulnerabilities
	local s = ""				-- the output string

	stdnse.print_debug(1, "vulscan: Found service " .. prod)

	-- Go into interactive mode
	if nmap.registry.args.vulscaninteractive == "1" then
		stdnse.print_debug(1, "vulscan: Enabling interactive mode ...")
		print("The scan has determined the following product:")
		print(prod)
		print("Press Enter to accept. Define new string to override.")
		local prod_override = io.stdin:read'*l'

		if string.len(prod_override) ~= 0 then
			prod = prod_override
			stdnse.print_debug(1, "vulscan: Product overwritten as " .. prod)
		end
	end

	-- Read custom report structure
	if nmap.registry.args.vulscanoutput ~= nil then
		if nmap.registry.args.vulscanoutput == "details" then
			struct = "[{id}] {title}\nMatches: {matches}, Prod: {product}, Ver: {version}\n{link}\n\n"
		elseif nmap.registry.args.vulscanoutput == "listid" then
			struct = "{id}\n"
		elseif nmap.registry.args.vulscanoutput == "listlink" then
			struct = "{link}\n"
		elseif nmap.registry.args.vulscanoutput == "listtitle" then
			struct = "{title}\n"
		else
			struct = nmap.registry.args.vulscanoutput
		end

		stdnse.print_debug(1, "vulscan: Custom output structure defined as " .. struct)
	end

	-- Read custom database link
	if nmap.registry.args.vulscandblink ~= nil then
		db_link = nmap.registry.args.vulscandblink
		stdnse.print_debug(1, "vulscan: Custom database link defined as " .. db_link)
	end

	if nmap.registry.args.vulscandb then
		stdnse.print_debug(1, "vulscan: Using single mode db " .. nmap.registry.args.vulscandb .. " ...")
		vul = find_vulnerabilities(prod, ver, nmap.registry.args.vulscandb)
		if #vul > 0 then
			s = s .. nmap.registry.args.vulscandb
			if db_link ~= "" then s = s .. " - " .. db_link end
			s = s .. ":\n" .. prepare_result(vul, struct, db_link) .. "\n\n"
		end
	else
		-- Add your own database, if you want to include it in the multi db mode
		db[1] = {name="CISA KEV",		file="known_exploited_vulnerabilities.csv",	url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",	link="https://nvd.nist.gov/vuln/detail/{id}"}
		db[2] = {name="Exploit-DB",		file="files_exploits.csv",			url="https://www.exploit-db.com",					link="https://www.exploit-db.com/exploits/{id}"}

		stdnse.print_debug(1, "vulscan: Using multi db mode (" .. #db .. " databases) ...")
		for i,v in ipairs(db) do
			vul = find_vulnerabilities(prod, ver, v.file)

			s = s .. v.name .. " - " .. v.url .. ":\n"
			if #vul > 0 then
					v_count = v_count + #vul
					s = s .. prepare_result(vul, struct, v.link) .. "\n"
			else
					s = s .. "No findings\n\n"
			end

			stdnse.print_debug(1, "vulscan: " .. #vul .. " matches in " .. v.file)
		end

		stdnse.print_debug(1, "vulscan: " .. v_count .. " matches in total")
	end

	if s then
		return s
	end
end

-- Find the product matches in the vulnerability databases
function find_vulnerabilities(prod, ver, db)
	local v = {}			-- matching vulnerabilities
	local v_id			-- id of vulnerability
	local v_title			-- title of vulnerability
	local v_title_lower		-- title of vulnerability in lowercase for speedup
	local v_found			-- if a match could be found

	-- Load database
	local v_entries = read_from_file("scripts/vulscan/" .. db)

	-- Clean useless dataparts (speeds up search and improves accuracy)
	prod = string.gsub(prod, " httpd", "")
	prod = string.gsub(prod, " smtpd", "")
	prod = string.gsub(prod, " ftpd", "")

	local prod_words = strsplit(" ", prod)

	stdnse.print_debug(1, "vulscan: Starting search of " .. prod ..
		" in " .. db ..
		" (" .. #v_entries .. " entries) ...")

	-- Iterate through the vulnerabilities in the database
	for i=1, #v_entries, 1 do
		v_id		= extract_from_table(v_entries[i], 1, ";")
		v_title		= extract_from_table(v_entries[i], 2, ";")

		if type(v_title) == "string" then
			v_title_lower = string.lower(v_title)

			-- Find the matches for the database entry
			for j=1, #prod_words, 1 do
				v_found = string.find(v_title_lower, escape(string.lower(prod_words[j])), 1)
				if type(v_found) == "number" then
					if #v == 0 then
						-- Initiate table
						v[1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					elseif v[#v].id ~= v_id then
						-- Create new entry
						v[#v+1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					else
						-- Add to current entry
						v[#v].product = v[#v].product .. " " .. prod_words[j]
						v[#v].matches = v[#v].matches+1
					end

					stdnse.print_debug(2, "vulscan: Match v_id " .. v_id ..
						" -> v[" .. #v .. "] " ..
						"(" .. v[#v].matches .. " match) " ..
						"(Prod: " .. prod_words[j] .. ")")
				end
			end

			-- Additional version matching
			if nmap.registry.args.vulscanversiondetection ~= "0" and ver ~= nil and ver ~= "" then
				if v[#v] ~= nil and v[#v].id == v_id then
					for k=0, string.len(ver)-1, 1 do
						v_version = string.sub(ver, 1, string.len(ver)-k)
						v_found = string.find(string.lower(v_title), string.lower(" " .. v_version), 1)

						if type(v_found) == "number" then
							v[#v].version = v[#v].version .. v_version .. " "
							v[#v].matches = v[#v].matches+1

							stdnse.print_debug(2, "vulscan: Match v_id " .. v_id ..
								" -> v[" .. #v .. "] " ..
								"(" .. v[#v].matches .. " match) " ..
								"(Version: " .. v_version .. ")")
						end
					end
				end
			end
		end
	end

	return v
end

-- Prepare the resulting matches
function prepare_result(v, struct, link)
	local grace = 0				-- grace trigger
	local match_max = 0			-- counter for maximum matches
	local match_max_title = ""	-- title of the maximum match
	local s = ""				-- the output string

	-- Search the entries with the best matches
	if #v > 0 then
		-- Find maximum matches
		for i=1, #v, 1 do
			if v[i].matches > match_max then
				match_max = v[i].matches
				match_max_title = v[i].title
			end
		end

		stdnse.print_debug(2, "vulscan: Maximum matches of a finding are " ..
			match_max .. " (" .. match_max_title .. ")")

		if match_max > 0 then
			for matchpoints=match_max, 1, -1 do
				for i=1, #v, 1 do
					if v[i].matches == matchpoints then
						stdnse.print_debug(2, "vulscan: Setting up result id " .. i)
						s = s .. report_parsing(v[i], struct, link)
					end
				end

				if nmap.registry.args.vulscanshowall ~= "1" and s ~= "" then
					-- If the next iteration shall be approached (increases matches)
					if grace == 0 then
						stdnse.print_debug(2, "vulscan: Best matches found in 1st pass. Going to use 2nd pass ...")
						grace = grace+1
					elseif nmap.registry.args.vulscanshowall ~= "1" then
						break
					end
				end
			end
		end
	end

	return s
end

-- Parse the report output structure
function report_parsing(v, struct, link)
	local s = struct

	--database data (needs to be first)
	s = string.gsub(s, "{link}", escape(link))

	--layout elements (needs to be second)
	s = string.gsub(s, "\\n", "\n")
	s = string.gsub(s, "\\t", "\t")

	--vulnerability data (needs to be third)
	s = string.gsub(s, "{id}", escape(v.id))
	s = string.gsub(s, "{title}", escape(v.title))
	s = string.gsub(s, "{matches}", escape(v.matches))
	s = string.gsub(s, "{product}", escape(v.product))	
	s = string.gsub(s, "{version}", escape(v.version))

	return s
end

-- Get the row of a CSV file
function extract_from_table(line, col, del)
	local val = strsplit(del, line)

	if type(val[col]) == "string" then
		return val[col]
	end
end

-- Read a file
function read_from_file(file)
	local filepath = nmap.fetchfile(file)

	if filepath then
		local f, err, _ = io.open(filepath, "r")
		if not f then
			stdnse.print_debug(1, "vulscan: Failed to open file" .. file)
		end

		local line, ret = nil, {}
		while true do
			line = f:read()
			if not line then break end
			ret[#ret+1] = line
		end

		f:close()

		return ret
	else
		stdnse.print_debug(1, "vulscan: File " .. file .. " not found")
		return ""
	end
end

-- We don't like unescaped things
function escape(s)
	s = string.gsub(s, "%%", "%%%%")
	return s
end
