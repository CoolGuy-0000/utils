// DataFlowTracer.cpp
//
// A WinDbg Extension that traces the origin of a value backwards in time using TTD.
// Command: !trace_origin <register>
//
// Example usage:
// !timetrack rax
// -> Traces RAX backwards.
// -> If RAX was loaded from [RCX+8], traces [RCX+8] backwards.
// -> If [RCX+8] was written by RDX, traces RDX backwards.
// -> Until a calculation, constant, or syscall is found.

#pragma comment(lib, "dbgeng.lib")

#include <Windows.h>
#include <assert.h>
#include <exception>
#include <stdexcept>
#include <vector>
#include <string>
#include <algorithm>
#include <format>
#include <iostream>
#include <sstream>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>

#define KDEXT_64BIT
#include <DbgEng.h>
#include <WDBGEXTS.H>
#include <atlcomcli.h>

using namespace TTD;
using namespace Replay;

struct OperationContext
{
    bool bMemory;
    uint64_t result;
};


WINDBG_EXTENSION_APIS64 ExtensionApis;

// Forward declarations
uint64_t GetRegisterValue(const AMD64_CONTEXT& context, const std::string& regName);
OperationContext CalculateEffectiveAddress(ICursor* cursor, ThreadId thread_id, std::string op);

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

template < typename Interface >
inline Interface* QueryInterfaceByIoctl()
{
    WDBGEXTS_QUERY_INTERFACE wqi = {};
    wqi.Iid = &__uuidof(Interface);
    auto const ioctlSuccess = Ioctl(IG_QUERY_TARGET_INTERFACE, &wqi, sizeof(wqi));
    if (!ioctlSuccess || wqi.Iface == nullptr)
    {
        throw std::invalid_argument("Unable to get TTD interface.");
    }
    return static_cast<Interface*>(wqi.Iface);
}

// Simple struct to hold Disassembly info
struct InstructionInfo
{
    std::string Mnemonic;
    std::string Op1;
    std::string Op2;
    std::string FullText;
};

// Use IDebugControl to disassemble instruction at current IP
InstructionInfo DisassembleCurrentInstr(IDebugClient* client, uint64_t ip)
{
    InstructionInfo info;
    CComQIPtr<IDebugControl> control(client);

    if (control)
    {
        char buffer[1024];
        ULONG64 endOffset;
        if (SUCCEEDED(control->Disassemble(ip, 0, buffer, sizeof(buffer), nullptr, &endOffset)))
        {
            info.FullText = buffer;
            // Extremely naive parsing for demonstration.
            // Format: "address opcode  mnemonic op1, op2"
            // Example: "00007ff7`3f8e1000 488b05f9ef0000 mov     rax,qword ptr [Processhacker!_security_cookie (00007ff7`3f8f0000)]"

            // We need to skip address and bytes.
            // WinDbg disassembly output varies by settings.
            // We will attempt to find the mnemonic.

            std::string line = buffer;

            // Remove newline
            if (!line.empty() && line.back() == '\n') line.pop_back();

            // Heuristic: Find first non-hex/address part?
            // Actually, let's just split by spaces and try to find the mnemonic.
            // Common mnemonics: mov, lea, add, sub, pop, call, syscall

            // A robust solution needs a real disassembler.
            // For now, we look for known keywords.
            std::stringstream ss(line);
            std::string token;
            std::vector<std::string> tokens;
            while (ss >> token) tokens.push_back(token);

            // Locate mnemonic (skip address/bytes)
            // Usually the mnemonic is the first "word" that is not a hex number.
            // But checking hex is hard.
            // Let's assume standard WinDbg output where mnemonic starts at some offset or index.
            // Actually, looking at the string might be easier.

            // Find "mov ", "lea ", "add ", "sub ", "pop ", "push "
            // We'll iterate tokens and find one that looks like an instruction.
            // This is very fragile.

            size_t mnemonicIdx = 0;
            for (size_t i = 0; i < tokens.size(); ++i) {
                std::string t = tokens[i];
                // basic check
                if (t == "mov" || t == "movzx" || t == "movsx" || t == "lea" ||
                    t == "add" || t == "sub" || t == "pop" || t == "push" ||
                    t == "call" || t == "syscall" || t == "xor" || t == "or" || t == "and")
                {
                    info.Mnemonic = t;
                    mnemonicIdx = i;
                    break;
                }
            }

            if (!info.Mnemonic.empty())
            {
                // Parse Operands. They are usually comma separated after mnemonic.
                // The tokens might be split by comma if spaces are around it.
                // Reconstruct the rest of the string.
                std::string remainder;
                for (size_t i = mnemonicIdx + 1; i < tokens.size(); ++i) {
                    if (i > mnemonicIdx + 1) remainder += " ";
                    remainder += tokens[i];
                }

                // Split by comma
                size_t comma = remainder.find(',');
                if (comma != std::string::npos) {
                    info.Op1 = remainder.substr(0, comma);
                    info.Op2 = remainder.substr(comma + 1);
                    // Trim spaces
                    info.Op2.erase(0, info.Op2.find_first_not_of(" "));
                }
                else {
                    info.Op1 = remainder;
                }
            }
        }
    }
    return info;
}

// ----------------------------------------------------------------------------
// Core Logic
// ----------------------------------------------------------------------------

ULONG GetCurrentThreadId(IDebugClient* client)
{
    CComQIPtr<IDebugSystemObjects4> pSystemObjects(client);

    if (pSystemObjects){
        ULONG systemThreadId = 0;

        if (SUCCEEDED(pSystemObjects->GetCurrentThreadSystemId(&systemThreadId)))
        {
			return systemThreadId;
        }
    }
    return (ULONG)-1;
}

enum class SourceType { Register, Memory, Constant, Calculation, Unknown, EndOfTrace };

struct TraceStep
{
    Position pos;
    SourceType type;
    std::string value; // Register name or Memory Address (hex string)
    std::string description;
};

// Find previous write to register
// Returns Position::Invalid if not found.
Position FindRegisterWrite(ULONG threadID, IReplayEngineView* engine, const std::string& regName, Position endPos)
{
    UniqueCursor cursor(engine->NewCursor());
    cursor->SetPosition(endPos);

    // Scan backwards.
    // We reuse the logic from previous task: Set Watchpoint on Execute, check for value change.
    // Optimization: Maybe we check every step? Yes.

    // Define context for callback
    struct RegSearchCtx {
        std::string targetReg;
        uint64_t lastValue;
        bool initialized;
        ThreadInfo thread_info;
        bool found;
        Position foundPos;
    } ctx;

    ctx.targetReg = regName;
    ctx.initialized = false;
	ctx.foundPos = Position::Invalid;
    ctx.found = false;

    ctx.thread_info = cursor->GetThreadInfo((ThreadId)threadID);
    cursor->GetThreadList();

    // We need to capture the initial value (at endPos) so we know when it changes.
    // The cursor is at endPos.
    AMD64_CONTEXT context = cursor->GetCrossPlatformContext().operator CROSS_PLATFORM_CONTEXT().Amd64Context;

    try {
        ctx.lastValue = GetRegisterValue(context, regName);
        ctx.initialized = true;
    }
    catch (...) {
        return Position::Invalid;
    }

    auto callback = [](uintptr_t c, ICursorView::MemoryWatchpointResult const&, IThreadView const* t) -> bool {
        RegSearchCtx* p = (RegSearchCtx*)c;

		if (p->thread_info != t->GetThreadInfo()) {
            return true;
        }

		AMD64_CONTEXT x = t->GetCrossPlatformContext().operator CROSS_PLATFORM_CONTEXT().Amd64Context;
        uint64_t val = 0;
        try { val = GetRegisterValue(x, p->targetReg); }
        catch (...) { return true; }

        if (val != p->lastValue && !p->found) {
            p->found = true;
            p->foundPos = t->GetPosition();
            return true;
        }
        return true;
    };

    cursor->AddMemoryWatchpoint({ GuestAddress::Null, UINT64_MAX, DataAccessMask::Execute });
    cursor->SetMemoryWatchpointCallback(callback, (uintptr_t)&ctx);
    cursor->SetEventMask(EventMask::MemoryWatchpoint);

    for (int i = 0; i < 10000 && !ctx.found; i++){ // Limit to 10k steps to avoid infinite
        cursor->ReplayBackward((StepCount)1);
    }

    return ctx.foundPos;
}

// Find previous write to memory
Position FindMemoryWrite(IReplayEngineView* engine, uint64_t address, uint64_t size, Position endPos)
{
    UniqueCursor cursor(engine->NewCursor());
    cursor->SetPosition(endPos);

    // TTD has direct support for memory watchpoints!
    // We want to find a WRITE to this address.

    // Wait, `ReplayBackward` will hit the last write.
    // We set a watchpoint on the address.
    cursor->AddMemoryWatchpoint({ (GuestAddress)address, size, DataAccessMask::Write });
    cursor->SetEventMask(EventMask::MemoryWatchpoint);

    // We don't need a manual callback to check values, the engine stops on write.
    // But we need to distinguish between multiple hits if we want specific one?
    // Usually the immediate backward replay hits the last write.

    ICursorView::ReplayResult result = cursor->ReplayBackward();
    if (result.StopReason == EventType::MemoryWatchpoint)
    {
        return cursor->GetPosition() - 1;
    }

    return Position::Invalid;
}

// ----------------------------------------------------------------------------
// Main Extension Logic
// ----------------------------------------------------------------------------


void AnalyzeTrace(IDebugClient* client, const std::string& startTarget)
{
    auto pEngine = QueryInterfaceByIoctl<IReplayEngineView>();
    auto pCursor = QueryInterfaceByIoctl<ICursorView>();

    ULONG threadID = GetCurrentThreadId(client);
    if (threadID == (ULONG)-1)
    {
        dprintf("Failed to get current thread ID.\n");
        return;
    }

    Position currentPos = pCursor->GetPosition((ThreadId)threadID);
    std::string currentTarget = startTarget;
    SourceType currentType = SourceType::Register; // Start assuming register

    // Check if input is likely memory address (hex)
    if (currentTarget.find("0x") == 0 || std::all_of(currentTarget.begin(), currentTarget.end(), ::isxdigit))
    {
        currentType = SourceType::Memory;
    }

    dprintf("Tracing origin of %s starting at %llX:%llX\n", currentTarget.c_str(), currentPos.Sequence, currentPos.Steps);

    int depth = 0;
    const int maxDepth = 100;

    while (depth < maxDepth)
    {
        depth++;
        dprintf("[%d] ", depth);

        Position foundPos = Position::Invalid;

        if (currentType == SourceType::Register)
        {
            dprintf("Searching for write to register %s... ", currentTarget.c_str());
            foundPos = FindRegisterWrite(threadID, pEngine, currentTarget, currentPos);
        }
        else if(currentType == SourceType::Memory)
        {
            uint64_t addr = 0;
            try {
                addr = std::stoull(currentTarget, nullptr, 16);
            }
            catch (...) {
                dprintf("Invalid address format.\n");
                break;
            }
            dprintf("Searching for write to memory %I64X... ", addr);
            foundPos = FindMemoryWrite(pEngine, addr, 8, currentPos); // Assuming 8 bytes for pointer/QWORD
        }

        if (foundPos == Position::Invalid)
        {
            dprintf("Origin not found (start of trace?).\n");
            break;
        }

        dprintf("Found at %I64X:%I64X\n", foundPos.Sequence, foundPos.Steps);

        // Move to found position to analyze
        currentPos = foundPos;

        // Disassemble
        // We need the IP at this position.
        UniqueCursor inspectCursor(pEngine->NewCursor());
        inspectCursor->SetPosition(foundPos);
        uint64_t ip = (uint64_t)inspectCursor->GetProgramCounter((ThreadId)threadID);

        InstructionInfo instr = DisassembleCurrentInstr(client, ip);
        dprintf("    %s\n", instr.FullText.c_str());

        // Parse Instruction to determine next step
        // Logic:
        // 1. MOV Reg, [Mem] -> Track Mem
        // 2. MOV Reg, Reg2  -> Track Reg2
        // 3. MOV [Mem], Reg -> Track Reg (If we were tracking Mem)
        // 4. POP Reg        -> Track [RSP] (Stack)
        // 5. LEA Reg, [Mem] -> STOP (Address origin)
        // 6. ADD/SUB...     -> STOP (Calculation)
        // 7. SYSCALL        -> STOP

        std::string mnem = instr.Mnemonic;
        std::string op1 = instr.Op1;
        std::string op2 = instr.Op2;

        // Normalize strings?
        // Assume lower case from DisassembleCurrentInstr

        bool isCalculation = (mnem == "add" || mnem == "sub" || mnem == "xor" || mnem == "or" || mnem == "and" || mnem == "inc" || mnem == "dec");

        if (mnem == "syscall" || mnem == "int")
        {
            dprintf("    Origin: System Call.\n");
            break;
        }

        if (isCalculation)
        {
            dprintf("    Origin: Calculation (%s).\n", mnem.c_str());
            break;
        }

        if (mnem == "lea")
        {
            dprintf("    Origin: Address Calculation (LEA).\n");
            break;
        }

        // Data Movement
        if (mnem == "mov" || mnem == "movzx" || mnem == "movsx")
        {
            OperationContext oc = CalculateEffectiveAddress(inspectCursor.get(), (ThreadId)threadID, op2);

            if (oc.bMemory) {
                dprintf("    Source is Memory: %s. Switching tracking to Memory.\n", op2.c_str());
                currentTarget = std::format("{:X}", oc.result);
                currentType = SourceType::Memory;
				continue;
            }
            else{
                dprintf("    Source is Register: %s. Switching tracking to Register.\n", op2.c_str());
                currentTarget = op2;
                currentType = SourceType::Register;
                continue;
            }
        }

        if (mnem == "pop")
        {
            // POP Reg -> Value comes from [RSP].
            // And RSP increases.
            // But at the *start* of instruction (foundPos), RSP points to the value.
            AMD64_CONTEXT ctx = inspectCursor->GetCrossPlatformContext((ThreadId)threadID).operator CROSS_PLATFORM_CONTEXT().Amd64Context;
            uint64_t stackPtr = ctx.Rsp;

            dprintf("    Source is Stack (POP). Switching tracking to Memory %I64X.\n", stackPtr);
            currentTarget = std::format("{:X}", stackPtr);
            currentType = SourceType::Memory;
            continue;
        }

        if (mnem == "push")
        {
            OperationContext oc = CalculateEffectiveAddress(inspectCursor.get(), (ThreadId)threadID, op1);

            if (oc.bMemory) {
                dprintf("    Source is Memory: %s. Switching tracking to Memory.\n", op1.c_str());
                currentTarget = std::format("{:X}", oc.result);
                currentType = SourceType::Memory;
                continue;
            }
            else {
                dprintf("    Source is Register: %s. Switching tracking to Register.\n", op1.c_str());
                currentTarget = op1;
                currentType = SourceType::Register;
                continue;
            }
        }

        dprintf("    Stopping: Unhandled or terminal instruction.\n");
        break;
    }
}

// ----------------------------------------------------------------------------
// DLL Exports
// ----------------------------------------------------------------------------

HRESULT CALLBACK timetrack(_Inout_ IDebugClient* const pClient, _In_ char const* const pArgs) noexcept
try
{
    if (pArgs == nullptr || strlen(pArgs) == 0)
    {
        dprintf("Usage: !timetrack <register>\n");
        return S_OK;
    }

    std::string arg = pArgs;

    arg.erase(0, arg.find_first_not_of(" "));
    arg.erase(arg.find_last_not_of(" ") + 1);

    AnalyzeTrace(pClient, arg);

    return S_OK;
}
catch (const std::exception& e)
{
    dprintf("Error: %s\n", e.what());
    return E_FAIL;
}
catch (...)
{
    return E_UNEXPECTED;
}

HRESULT CALLBACK DebugExtensionInitialize(_Out_ ULONG* pVersion, _Out_ ULONG* pFlags) noexcept
{
    *pVersion = DEBUG_EXTENSION_VERSION(1, 0);
    *pFlags = 0;

	CComPtr<IDebugClient> client;
    if (SUCCEEDED(DebugCreate(IID_PPV_ARGS(&client))))
    {
        CComQIPtr<IDebugControl> control(client);
        if(control){
            ExtensionApis.nSize = sizeof(ExtensionApis);
            control->GetWindbgExtensionApis64(&ExtensionApis);
        }
    }

    return S_OK;
}

void CALLBACK DebugExtensionUninitialize() noexcept {}

// ----------------------------------------------------------------------------
// Utils Implementation
// ----------------------------------------------------------------------------

uint64_t GetRegisterValue(const AMD64_CONTEXT& context, const std::string& regName)
{
    std::string upperReg = regName;
    std::transform(upperReg.begin(), upperReg.end(), upperReg.begin(), ::toupper);

    if (upperReg == "RAX" || upperReg == "EAX" || upperReg == "AX" || upperReg == "AL") return context.Rax;
    if (upperReg == "RBX" || upperReg == "EBX" || upperReg == "BX" || upperReg == "BL") return context.Rbx;
    if (upperReg == "RCX" || upperReg == "ECX" || upperReg == "CX" || upperReg == "CL") return context.Rcx;
    if (upperReg == "RDX" || upperReg == "EDX" || upperReg == "DX" || upperReg == "DL") return context.Rdx;
    if (upperReg == "RSI") return context.Rsi;
    if (upperReg == "RDI") return context.Rdi;
    if (upperReg == "RBP") return context.Rbp;
    if (upperReg == "RSP") return context.Rsp;
    if (upperReg == "R8")  return context.R8;
    if (upperReg == "R9")  return context.R9;
    if (upperReg == "R10") return context.R10;
    if (upperReg == "R11") return context.R11;
    if (upperReg == "R12") return context.R12;
    if (upperReg == "R13") return context.R13;
    if (upperReg == "R14") return context.R14;
    if (upperReg == "R15") return context.R15;
    if (upperReg == "RIP") return context.Rip;

    throw std::runtime_error("Unknown register: " + regName);
}


std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string ToUpper(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

uint64_t ParseNumber(std::string str) {
    str = Trim(str);
    if (str.empty()) return 0;

    try {
        // Hex with 0x prefix
        if (str.size() > 2 && str.substr(0, 2) == "0x") {
            return std::stoull(str, nullptr, 16);
        }
        // Hex with h suffix (WinDbg style)
        if (str.back() == 'h' || str.back() == 'H') {
            return std::stoull(str.substr(0, str.size() - 1), nullptr, 16);
        }
        // Hex with ` symbol (WinDbg sometimes uses ` for 64bit separator, removing it)
        str.erase(std::remove(str.begin(), str.end(), '`'), str.end());

        return std::stoull(str, nullptr, 16);
    }
    catch (...) {
        return 0;
    }
}

uint64_t EvaluateTerm(const AMD64_CONTEXT& ctx, std::string term) {
    term = Trim(term);
    if (term.empty()) return 0;

    size_t starPos = term.find('*');
    if (starPos != std::string::npos) {
        std::string left = term.substr(0, starPos);
        std::string right = term.substr(starPos + 1);

        uint64_t val1 = 0;
        uint64_t val2 = 0;

        if (isdigit(Trim(left)[0])) val1 = ParseNumber(left);
        else val1 = GetRegisterValue(ctx, left);

        if (isdigit(Trim(right)[0])) val2 = ParseNumber(right);
        else val2 = GetRegisterValue(ctx, right);

        return val1 * val2;
    }

    if (isdigit(term[0]) || (term.size() > 1 && term.substr(0, 2) == "0x")) {
        return ParseNumber(term);
    }

    return GetRegisterValue(ctx, term);
}

OperationContext CalculateEffectiveAddress(ICursor* cursor, ThreadId thread_id, std::string op) {
    OperationContext result = {};
    result.result = 0;

    size_t bracketStart = op.find('[');
    size_t bracketEnd = op.find_last_of(']');

    if (bracketStart != std::string::npos && bracketEnd != std::string::npos && bracketEnd > bracketStart) {
        result.bMemory = true;

        std::string content = op.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

        AMD64_CONTEXT ctx = cursor->GetCrossPlatformContext(thread_id).operator CROSS_PLATFORM_CONTEXT().Amd64Context;

        uint64_t currentAddress = 0;
        char currentOp = '+';

        std::string buffer;

        content += "+";

        for (size_t i = 0; i < content.size(); ++i) {
            char c = content[i];

            if (c == '+' || c == '-') {

                uint64_t termValue = EvaluateTerm(ctx, buffer);

                if (currentOp == '+') {
                    currentAddress += termValue;
                }
                else if (currentOp == '-') {
                    currentAddress -= termValue;
                }

                currentOp = c;
                buffer = "";
            }
            else {
                buffer += c;
            }
        }

        result.result = currentAddress;
    }
    else result.bMemory = false;

    return result;
}
