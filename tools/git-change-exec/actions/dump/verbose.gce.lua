function match(lf, ld)
	return true
end

function exec(as)
	print(#as)
	for _, a in as() do
		print("path: " .. a.Path .. " lineDiff: " .. a.Ld:String())
	end
	return true
end
