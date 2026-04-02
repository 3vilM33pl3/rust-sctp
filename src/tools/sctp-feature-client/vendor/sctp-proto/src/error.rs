use alloc::string::String;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Errors triggered during SCTP association operation
#[derive(Debug, Eq, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ErrChunkHeaderTooSmall,
    ErrChunkHeaderNotEnoughSpace,
    ErrChunkHeaderPaddingNonZero,
    ErrChunkHeaderInvalidLength,

    ErrChunkTypeNotAbort,
    ErrBuildAbortChunkFailed,
    ErrChunkTypeNotCookieAck,
    ErrChunkTypeNotCookieEcho,
    ErrChunkTypeNotCt,
    ErrBuildErrorChunkFailed,
    ErrMarshalStreamFailed,
    ErrChunkTooShort,
    ErrChunkTypeNotForwardTsn,
    ErrChunkTypeNotHeartbeat,
    ErrChunkTypeNotHeartbeatAck,
    ErrHeartbeatNotLongEnoughInfo,
    ErrParseParamTypeFailed,
    ErrHeartbeatParam,
    ErrHeartbeatChunkUnmarshal,
    ErrUnimplemented,
    ErrHeartbeatAckParams,
    ErrHeartbeatAckNotHeartbeatInfo,
    ErrHeartbeatAckMarshalParam,

    ErrErrorCauseTooSmall,

    ErrParamTypeUnhandled { typ: u16 },

    ErrParamTypeUnexpected,

    ErrParamHeaderTooShort,
    ErrParamHeaderSelfReportedLengthShorter,
    ErrParamHeaderSelfReportedLengthLonger,
    ErrParamHeaderParseFailed,

    ErrParamPacketTooShort,
    ErrSsnResetRequestParamTooShort,
    ErrReconfigRespParamTooShort,
    ErrInvalidAlgorithmType,

    ErrInitChunkParseParamTypeFailed,
    ErrInitChunkUnmarshalParam,
    ErrInitAckMarshalParam,

    ErrChunkTypeNotTypeInit,
    ErrChunkValueNotLongEnough,
    ErrChunkTypeInitFlagZero,
    ErrChunkTypeInitUnmarshalFailed,
    ErrChunkTypeInitMarshalFailed,
    ErrChunkTypeInitInitiateTagZero,
    ErrInitInboundStreamRequestZero,
    ErrInitOutboundStreamRequestZero,
    ErrInitAdvertisedReceiver1500,

    ErrChunkPayloadSmall,
    ErrChunkTypeNotPayloadData,
    ErrChunkTypeNotReconfig,
    ErrChunkReconfigInvalidParamA,

    ErrChunkParseParamTypeFailed,
    ErrChunkMarshalParamAReconfigFailed,
    ErrChunkMarshalParamBReconfigFailed,

    ErrChunkTypeNotSack,
    ErrSackSizeNotLargeEnoughInfo,

    ErrInvalidChunkSize,
    ErrChunkTypeNotShutdown,

    ErrChunkTypeNotShutdownAck,
    ErrChunkTypeNotShutdownComplete,

    ErrPacketRawTooSmall,
    ErrParseSctpChunkNotEnoughData,
    ErrUnmarshalUnknownChunkType,
    ErrChecksumMismatch,

    ErrUnexpectedChuckPoppedUnordered,
    ErrUnexpectedChuckPoppedOrdered,
    ErrUnexpectedQState,
    ErrTryAgain,

    ErrAbortChunk(String),
    ErrShutdownNonEstablished,
    ErrAssociationClosedBeforeConn,
    ErrAssociationInitFailed,
    ErrAssociationHandshakeClosed,
    ErrSilentlyDiscard,
    ErrInitNotStoredToSend,
    ErrCookieEchoNotStoredToSend,
    ErrSctpPacketSourcePortZero,
    ErrSctpPacketDestinationPortZero,
    ErrInitChunkBundled,
    ErrInitChunkVerifyTagNotZero,
    ErrHandleInitState,
    ErrInitAckNoCookie,
    ErrStreamAlreadyExist,
    ErrStreamResetPending,
    ErrStreamCreateFailed,
    ErrInflightQueueTsnPop,
    ErrTsnRequestNotExist,
    ErrResetPacketInStateNotExist,
    ErrParameterType,
    ErrPayloadDataStateNotExist,
    ErrChunkTypeUnhandled,
    ErrHandshakeInitAck,
    ErrHandshakeCookieEcho,
    ErrOutboundPacketTooLarge,
    ErrInboundPacketTooLarge,
    ErrStreamClosed,
    ErrStreamNotExisted,
    ErrShortBuffer,
    ErrEof,
    ErrInvalidSystemTime,
    ErrNetConnRead,
    ErrMaxDataChannelID,

    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for Error {}
