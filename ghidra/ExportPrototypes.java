// Writes the function prototypes in a Ghidra type archive as one C-like line each, with types
// reduced to what recore's prototype table uses: sized integers, floats, strings and pointers.
// Arguments: <archive.gdt> <output file> [long]. Lines read `<convention> <return> <name>(<params>)`.
// With `long`, the C types long and unsigned long are written by name and not by their size in
// the archive: they are 4 bytes on Windows and on 32-bit targets and 8 elsewhere, so one table
// then serves both, and the 32-bit macOS archive serves 64-bit macOS.
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class ExportPrototypes extends GhidraScript {
    // Typedefs that are as wide as a pointer whatever they are built from.
    private static final Set<String> POINTER_SIZED = Set.of("size_t", "SIZE_T", "ULONG_PTR", "UINT_PTR", "DWORD_PTR",
        "uintptr_t", "WPARAM", "LONG_PTR", "INT_PTR", "SSIZE_T", "intptr_t", "ptrdiff_t", "LPARAM", "LRESULT");
    private static final Set<String> RESERVED = Set.of("int", "uint", "char", "void", "bool", "float", "double", "long",
        "short", "unsigned", "signed", "struct", "union", "enum", "const", "typedef", "extern", "code", "size_t",
        "DWORD", "BOOL", "HANDLE", "wstr", "ulong", "string", "this", "class", "template", "default", "register", "volatile",
        "static", "return", "if", "else", "for", "while", "do", "switch", "case", "break", "continue", "goto", "sizeof");

    // Write long and unsigned long as `long` and `ulong`.
    private static boolean namedLong = false;

    private static DataType base(DataType type) {
        while (type instanceof TypeDef) type = ((TypeDef) type).getDataType();
        return type;
    }

    // The reduced spelling of a type, or null for one passed by value that has no such spelling.
    private static String spell(DataType type) {
        for (DataType t = type; t instanceof TypeDef; t = ((TypeDef) t).getDataType()) {
            if (POINTER_SIZED.contains(t.getName())) return "size_t";
        }
        DataType plain = base(type);
        if (plain == null || plain instanceof VoidDataType) return "void";
        if (plain instanceof Pointer) {
            DataType target = base(((Pointer) plain).getDataType());
            if (target instanceof CharDataType || target instanceof SignedCharDataType) return "char *";
            if (target instanceof WideCharDataType || target instanceof WideChar16DataType) return "wstr";
            // Keep what a pointer to a number points at; everything else is opaque.
            String pointee = target instanceof AbstractIntegerDataType || target instanceof AbstractFloatDataType ? spell(target) : null;
            return pointee == null ? "void *" : pointee + " *";
        }
        int size = plain.getLength();
        if (plain instanceof ghidra.program.model.data.Enum) return "uint" + Math.max(size, 1);
        if (plain instanceof BooleanDataType) return "uint1";
        if (plain instanceof AbstractFloatDataType) return "float" + size;
        if (namedLong && plain instanceof LongDataType) return "long";
        if (namedLong && plain instanceof UnsignedLongDataType) return "ulong";
        if (plain instanceof AbstractIntegerDataType) {
            boolean signed = ((AbstractIntegerDataType) plain).isSigned();
            return (signed ? "int" : "uint") + size;
        }
        if (plain instanceof FunctionDefinition) return "void *";
        if (plain instanceof Undefined || plain instanceof DefaultDataType) return size > 0 && size <= 8 ? "uint" + size : null;
        return null;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        namedLong = args.length > 2 && args[2].equals("long");
        FileDataTypeManager archive = FileDataTypeManager.openFileArchive(new File(args[0]), false);
        TreeMap<String, String> lines = new TreeMap<>();
        Iterator<DataType> all = archive.getAllDataTypes();
        while (all.hasNext()) {
            DataType type = all.next();
            if (!(type instanceof FunctionDefinition)) continue;
            FunctionDefinition function = (FunctionDefinition) type;
            String name = function.getName();
            if (!name.matches("[A-Za-z_][A-Za-z0-9_]*")) continue;
            String returns = spell(function.getReturnType());
            if (returns == null) continue;
            List<String> params = new ArrayList<>();
            boolean spelled = true;
            ParameterDefinition[] arguments = function.getArguments();
            for (int index = 0; index < arguments.length; index++) {
                String spelling = spell(arguments[index].getDataType());
                if (spelling == null || spelling.equals("void")) { spelled = false; break; }
                String param = arguments[index].getName();
                if (param == null || !param.matches("[A-Za-z_][A-Za-z0-9_]*") || RESERVED.contains(param)
                    || param.matches("u?int[0-9]+|float[0-9]+|wchar[0-9]+|undefined[0-9]+")) {
                    param = "param_" + (index + 1);
                }
                params.add(spelling.endsWith("*") ? spelling + param : spelling + " " + param);
            }
            if (!spelled) continue;
            if (function.hasVarArgs()) params.add("...");
            String convention = function.getCallingConventionName();
            convention = convention == null || convention.startsWith("unknown") || convention.equals("default") ? "-" : convention.replace("__", "");
            lines.put(name, convention + " " + returns + (returns.endsWith("*") ? "" : " ") + name + "(" + (params.isEmpty() ? "void" : String.join(", ", params)) + ")");
        }
        try (PrintWriter out = new PrintWriter(args[1])) {
            for (String line : lines.values()) out.println(line);
        }
        println("PROTOTYPES " + lines.size());
        archive.close();
    }
}
