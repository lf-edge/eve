function isDnsmasq(path)
    pattern = "^/?pkg/alpine/.*$"
    return path:find(pattern) ~= nil
end

function match(lf, ld)
    if not isDnsmasq(lf:Path()) then
        return false
    end
    if ld:IsCommentString() == "comment" then
        return false
    end

    return true
end

function exec()
    ok, _, _ = os.execute("make -C pkg/alpine/dnstest test")
    return ok
end
