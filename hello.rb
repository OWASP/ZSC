=begin
def test(a1 = "Ruby", a2 = "Perl")
   puts "The programming language is #{a1}"
   puts "The programming language is #{a2}"
end
test "C", "C++"
test
=end
require "base64"
def rot13(t)
   for i in 0..t.size-1   
      x = t[i].ord
      x = (x-97+13) % 26+97 if x.between?(97,122) 
      x = (x-65+13) % 26+65 if x.between?(65,90)
      t[i] = x.chr                             
   end
   return t
end 

gvIUCZbYjItqdjcZQnxwgSMOgJeTwxkQOMQJZGsomXacBPANNJ= <<'EOF'
qrs grfg(n1 = "Ehol", n2 = "Crey")
   chgf "Gur cebtenzzvat ynathntr vf #{n1}"
   chgf "Gur cebtenzzvat ynathntr vf #{n2}"
raq
grfg "P", "P++"
grfg
EOF

def ghNqQdJEoHeycdKlvoCFgRHMesNYyTaCSqjxRnrorZsiKTrvLX(oeGVxsNbsIarnScgQWJzbtrhJiiwFwZPTJFVfNyspVSPVPKUWzs)
    vMOBjbMDtRwqWZkjKwzCkXtxshgVcYzcdPKKKREXBHsKwRYbbDr = rot13((oeGVxsNbsIarnScgQWJzbtrhJiiwFwZPTJFVfNyspVSPVPKUWzs))
    return vMOBjbMDtRwqWZkjKwzCkXtxshgVcYzcdPKKKREXBHsKwRYbbDr
end
eval(ghNqQdJEoHeycdKlvoCFgRHMesNYyTaCSqjxRnrorZsiKTrvLX(gvIUCZbYjItqdjcZQnxwgSMOgJeTwxkQOMQJZGsomXacBPANNJ));
