function isVTPM(path)
    pattern = "^/?pkg/vtpm/.*$"
    return path:find(pattern) ~= nil
end

function match(lf, ld)
    if not isVTPM(lf:Path()) then
        return false
    end
    if ld:IsCommentString() == "comment" then
        return false
    end

    return true
end

function exec()
    ok, _, _ = os.execute("make -C pkg/vtpm test")
    return ok
end
